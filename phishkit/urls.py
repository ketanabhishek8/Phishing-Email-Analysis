"""Extract every link from the email body and score how suspicious each one looks."""

from __future__ import annotations

import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import urlsplit

from .domains import (
    FREE_HOSTING, SHORTENERS, SUSPICIOUS_TLDS, brand_tokens, decode_idn, domain_of, is_punycode,
    legit_brand_for, lookalike_of, org_domain, same_org, tld,
)
from .models import Finding, Severity
from .parser import ParsedEmail

CATEGORY = "urls"

_TEXT_URL = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'`]+")
_TRAILING = ".,;:!?'\"*"
_ANCHOR_DOMAIN = re.compile(r"(?i)(?:^|[\s(<\[])((https?://|www\.)?((?:[a-z0-9-]+\.)+([a-z]{2,24})))(?=[/:?#\s)>\],.]|$)")
# TLDs accepted when link text shows a bare domain without http:// or www.
_COMMON_TLDS = {
    "com", "org", "net", "gov", "edu", "mil", "int", "io", "co", "uk", "us", "ca", "au", "in",
    "de", "fr", "nl", "it", "es", "jp", "cn", "ru", "br", "info", "biz", "me", "app", "dev",
} | SUSPICIOUS_TLDS
_SKIP_SCHEMES = ("mailto:", "tel:", "cid:", "#", "sms:")

# flag -> (severity, finding title, explanation)
FLAGS = {
    "dangerous_scheme": (Severity.HIGH, "Link uses a script or data URI",
                         "javascript: and data: links run code or render attacker content directly in the client."),
    "text_mismatch": (Severity.HIGH, "Link text shows a different domain",
                      "The visible link text names one site but clicking goes somewhere else, a classic phishing trick."),
    "ip_host": (Severity.HIGH, "Link points to a raw IP address",
                "Legitimate organisations link to their domain names, not bare IP addresses."),
    "punycode": (Severity.HIGH, "Punycode (internationalised) domain in link",
                 "The domain uses non-Latin characters that can look identical to a trusted brand."),
    "lookalike": (Severity.HIGH, "Link to a lookalike domain",
                  "The link's domain imitates a well-known brand."),
    "brand_in_subdomain": (Severity.HIGH, "Brand name used in an unrelated domain",
                           "A brand appears in the subdomain (e.g. paypal.com.evil.xyz) to look trustworthy, "
                           "but the real owner is the domain at the end."),
    "userinfo": (Severity.HIGH, "Link hides its real host with an @",
                 "Everything before the @ in a URL is ignored; the browser goes to the host after it."),
    "form": (Severity.HIGH, "HTML form in email body",
             "Forms inside emails are used to collect credentials directly; legitimate senders link to their site."),
    "shortener": (Severity.MEDIUM, "URL shortener hides the destination",
                  "Shortened links conceal where they lead and are popular for evading filters."),
    "free_hosting": (Severity.MEDIUM, "Link hosted on a free hosting or tunnelling platform",
                     "Anyone can publish on these platforms in minutes, so they are common for throwaway phishing pages."),
    "brand_in_path": (Severity.MEDIUM, "Brand name in link path on unrelated domain",
                      "A brand name in the path (e.g. /office365/login) on a domain that brand does not own."),
    "suspicious_tld": (Severity.LOW, "Link uses a high-abuse top-level domain",
                       "This TLD is cheap and disproportionately used for phishing and malware."),
    "insecure": (Severity.LOW, "Unencrypted (http) link",
                 "The link does not use HTTPS."),
    "many_subdomains": (Severity.LOW, "Unusually deep subdomain chain",
                        "Long chains of subdomains are used to push the real domain out of view on mobile screens."),
    "long_url": (Severity.LOW, "Very long URL",
                 "Very long URLs can hide the real destination or carry encoded victim data."),
}


def defang(url: str) -> str:
    """Make a URL non-clickable for reports: hxxps://evil[.]com/path."""
    lowered = url.lower()
    if lowered.startswith(("javascript:", "data:")):
        return url[:80] + ("..." if len(url) > 80 else "")
    out = re.sub(r"(?i)^http", "hxxp", url)
    match = re.match(r"(?i)^([a-z]+://)?([^/?#]+)(.*)$", out)
    if not match:
        return out.replace(".", "[.]")
    scheme, host, rest = match.group(1) or "", match.group(2), match.group(3)
    return scheme + host.replace(".", "[.]") + rest


def _clean_text_url(url: str) -> str:
    url = url.rstrip(_TRAILING)
    while url.endswith(")") and url.count(")") > url.count("("):
        url = url[:-1].rstrip(_TRAILING)
    return url


class _LinkCollector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str, str]] = []  # (url, source, anchor text)
        self._anchor: list | None = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ("a", "area") and attrs.get("href"):
            if tag == "a":
                self._anchor = [attrs["href"], []]
            else:
                self.links.append((attrs["href"], "html:area", ""))
        elif tag == "form":
            self.links.append((attrs.get("action") or "", "html:form", ""))
        elif tag in ("iframe", "frame", "embed", "script") and attrs.get("src"):
            self.links.append((attrs["src"], f"html:{tag}", ""))
        elif tag == "meta" and (attrs.get("http-equiv") or "").lower() == "refresh":
            match = re.search(r"(?i)url\s*=\s*['\"]?([^'\"]+)", attrs.get("content") or "")
            if match:
                self.links.append((match.group(1).strip(), "html:meta-refresh", ""))

    def handle_data(self, data):
        if self._anchor is not None:
            self._anchor[1].append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._anchor is not None:
            href, text = self._anchor
            self.links.append((href, "html:a", " ".join("".join(text).split())))
            self._anchor = None


def extract_urls(text: str, html: str) -> list[dict]:
    found: dict[str, dict] = {}

    def add(url: str, source: str, anchor: str = ""):
        url = (url or "").strip()
        if source == "html:form" and not url:
            url = "(form with no action)"
        if not url or url.lower().startswith(_SKIP_SCHEMES):
            return
        entry = found.setdefault(url, {"url": url, "sources": [], "anchor_texts": []})
        if source not in entry["sources"]:
            entry["sources"].append(source)
        if anchor and anchor not in entry["anchor_texts"]:
            entry["anchor_texts"].append(anchor)

    for match in _TEXT_URL.finditer(text or ""):
        add(_clean_text_url(match.group(0)), "text")
    if html:
        collector = _LinkCollector()
        try:
            collector.feed(html)
            collector.close()
        except Exception:  # malformed HTML: keep whatever was collected
            pass
        for url, source, anchor in collector.links:
            add(url, source, anchor)
    return list(found.values())


def _host(url: str) -> tuple[str, str, bool]:
    """Return (hostname, scheme, has_userinfo)."""
    target = url if re.match(r"(?i)^[a-z][a-z0-9+.-]*:", url) else "http://" + url
    try:
        parts = urlsplit(target)
        host = (parts.hostname or "").lower().rstrip(".")
        return host, parts.scheme.lower(), "@" in (parts.netloc or "")
    except ValueError:
        return "", "", False


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return bool(re.fullmatch(r"\d+", host))  # decimal-encoded IPs like http://3232235777/


def _domain_in_text(text: str) -> str:
    """Domain that link text visibly claims, e.g. 'https://www.paypal.com/signin' or 'paypal.com'."""
    for match in _ANCHOR_DOMAIN.finditer(text):
        prefix, domain, suffix = match.group(2), match.group(3).lower(), match.group(4).lower()
        if prefix or suffix in _COMMON_TLDS:
            return domain
    return ""


def _flags(entry: dict, from_domain: str) -> tuple[str, list[str]]:
    url = entry["url"]
    flags: list[str] = []
    lowered = url.lower()

    if "html:form" in entry["sources"]:
        flags.append("form")
    if lowered.startswith(("javascript:", "data:", "vbscript:")):
        flags.append("dangerous_scheme")
        return "", flags

    host, scheme, userinfo = _host(url)
    if not host:
        return "", flags
    legit = legit_brand_for(host)

    if userinfo:
        flags.append("userinfo")
    if _is_ip(host):
        flags.append("ip_host")
    else:
        if is_punycode(host):
            flags.append("punycode")
        if lookalike_of(host):
            flags.append("lookalike")
        org = org_domain(host)
        if org in SHORTENERS or host in SHORTENERS:
            flags.append("shortener")
        if any(host == d or host.endswith("." + d) for d in FREE_HOSTING):
            flags.append("free_hosting")
        if tld(host) in SUSPICIOUS_TLDS:
            flags.append("suspicious_tld")
        subdomain = host[: -len(org)].rstrip(".") if host != org else ""
        if subdomain.count(".") >= 3:
            flags.append("many_subdomains")
        if not legit:
            sub_tokens = set(re.split(r"[.\-_]", decode_idn(subdomain)))
            path = lowered.split(host, 1)[-1]
            path_tokens = set(re.split(r"[^a-z0-9]+", path))
            for _, token, _ in brand_tokens():
                if token in sub_tokens and "brand_in_subdomain" not in flags:
                    flags.append("brand_in_subdomain")
                if len(token) >= 5 and token in path_tokens and "brand_in_path" not in flags:
                    flags.append("brand_in_path")

    if scheme == "http":
        flags.append("insecure")
    if len(url) > 200:
        flags.append("long_url")

    for anchor in entry["anchor_texts"]:
        shown = _domain_in_text(anchor)
        if shown and not same_org(shown, host):
            flags.append("text_mismatch")
            break

    if "form" in flags and from_domain and same_org(host, from_domain):
        flags.remove("form")
        flags.append("form_same_domain")
    return host, flags


def analyze_urls(email: ParsedEmail) -> tuple[list[dict], list[Finding]]:
    from_domain = domain_of(email.from_)
    entries = extract_urls(email.text_body, email.html_body)
    by_flag: dict[str, list[str]] = {}
    for entry in entries:
        host, flags = _flags(entry, from_domain)
        entry["domain"] = host
        entry["defanged"] = defang(entry["url"])
        entry["flags"] = flags
        for flag in flags:
            by_flag.setdefault(flag, []).append(entry["defanged"])

    findings = []
    for flag, (severity, title, detail) in FLAGS.items():
        hits = by_flag.get(flag)
        if not hits:
            continue
        count = f"{len(hits)} link" + ("s" if len(hits) != 1 else "")
        findings.append(Finding(CATEGORY, severity, title, f"{detail} ({count})",
                                "; ".join(hits[:3]) + (" ..." if len(hits) > 3 else "")))
    if "form_same_domain" in by_flag:
        findings.append(Finding(CATEGORY, Severity.MEDIUM, "HTML form in email body",
                                "The email contains a form that submits to the sender's own domain. "
                                "Unusual: legitimate senders link to their site instead.",
                                by_flag["form_same_domain"][0]))
    return entries, findings
