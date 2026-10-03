"""Domain helpers: organisational domains, IDN/punycode and brand lookalike detection."""

from __future__ import annotations

import re
import unicodedata

# A small built-in subset of the Public Suffix List: multi-label suffixes that are
# common in mail traffic, plus free hosting platforms where every subdomain belongs
# to a different owner (phishers love these).
MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "nhs.uk",
    "com.au", "net.au", "org.au", "gov.au", "edu.au",
    "co.nz", "org.nz", "govt.nz",
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "firm.in", "gen.in",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "com.br", "com.cn", "com.mx", "co.za", "com.sg", "com.hk", "com.tr", "co.kr",
    "com.ar", "com.my", "com.ph", "com.pk", "co.id", "com.ng", "com.eg", "com.sa",
    "github.io", "gitlab.io", "herokuapp.com", "blogspot.com", "azurewebsites.net",
    "web.app", "firebaseapp.com", "pages.dev", "workers.dev", "netlify.app", "vercel.app",
    "appspot.com", "glitch.me", "repl.co", "weebly.com", "wixsite.com", "000webhostapp.com",
    "s3.amazonaws.com", "r2.dev", "ngrok.io", "ngrok-free.app", "trycloudflare.com",
}

# Brand -> (names that may appear in display names / URLs, legitimate domains).
# The first legitimate domain is the one reported as "imitated".
BRANDS: dict[str, tuple[list[str], list[str]]] = {
    "paypal": (["paypal"], ["paypal.com", "paypal.me", "paypalobjects.com"]),
    "microsoft": (
        ["microsoft", "office365", "office 365", "microsoft 365", "outlook", "onedrive", "sharepoint"],
        ["microsoft.com", "microsoftonline.com", "office.com", "office365.com", "outlook.com",
         "live.com", "hotmail.com", "sharepoint.com", "onmicrosoft.com", "azure.com",
         "windows.net", "msn.com", "microsoft365.com", "onedrive.com"],
    ),
    "apple": (["apple", "icloud", "itunes"], ["apple.com", "icloud.com", "me.com", "itunes.com"]),
    "amazon": (["amazon", "aws"], ["amazon.com", "amazon.co.uk", "amazon.in", "amazon.de",
                                   "amazonses.com", "amazonaws.com", "amazon.ca"]),
    "google": (["google", "gmail"], ["google.com", "gmail.com", "googlemail.com", "youtube.com",
                                     "googleusercontent.com", "goo.gl"]),
    "netflix": (["netflix"], ["netflix.com"]),
    "docusign": (["docusign"], ["docusign.com", "docusign.net"]),
    "dropbox": (["dropbox"], ["dropbox.com", "dropboxmail.com"]),
    "linkedin": (["linkedin"], ["linkedin.com"]),
    "facebook": (["facebook", "instagram", "meta"], ["facebook.com", "facebookmail.com", "meta.com",
                                                     "instagram.com"]),
    "dhl": (["dhl"], ["dhl.com", "dhl.de"]),
    "fedex": (["fedex"], ["fedex.com"]),
    "usps": (["usps"], ["usps.com"]),
    "wellsfargo": (["wells fargo", "wellsfargo"], ["wellsfargo.com"]),
    "chase": (["chase bank", "jpmorgan chase", "chase"], ["chase.com", "jpmorgan.com"]),
    "bankofamerica": (["bank of america", "bankofamerica"], ["bankofamerica.com", "bofa.com"]),
    "adobe": (["adobe"], ["adobe.com"]),
    "coinbase": (["coinbase"], ["coinbase.com"]),
    "irs": (["irs", "internal revenue service"], ["irs.gov"]),
    "hmrc": (["hmrc"], ["hmrc.gov.uk", "gov.uk"]),
}

FREEMAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "outlook.com", "hotmail.com",
    "live.com", "msn.com", "aol.com", "icloud.com", "me.com", "proton.me", "protonmail.com",
    "gmx.com", "gmx.de", "mail.com", "yandex.com", "yandex.ru", "zoho.com", "tutanota.com",
    "mail.ru", "rediffmail.com", "qq.com", "163.com",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "bit.do", "s.id", "v.gd", "lnkd.in",
    "qrco.de", "shorte.st", "adf.ly",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "link", "work", "support", "rest", "fit", "gq", "ml",
    "cf", "tk", "ga", "buzz", "monster", "cam", "icu", "sbs", "cfd", "quest", "country",
    "kim", "loan", "men", "date", "racing", "review", "stream", "download", "ru", "su",
}

# Words phishers bolt onto a brand to build a convincing domain.
BAIT_WORDS = (
    "secure", "security", "login", "logon", "signin", "verify", "verification", "account",
    "support", "update", "service", "billing", "auth", "online", "help", "alert", "confirm",
    "recovery", "unlock", "wallet", "payment", "invoice", "helpdesk", "portal",
)

# Visually confusable non-Latin characters mapped to the Latin letter they imitate.
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
    "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ɡ": "g", "ո": "n", "ս": "u", "ⅼ": "l",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "κ": "k", "ι": "i", "ε": "e",
    "Ꭺ": "a", "ӏ": "l", "ɑ": "a",
})

# Character tricks that survive in plain ASCII.
_ASCII_SWAPS = [("rn", "m"), ("vv", "w"), ("cl", "d"), ("0", "o"), ("1", "l"), ("3", "e"),
                ("4", "a"), ("5", "s"), ("7", "t"), ("@", "a"), ("$", "s")]

_ADDR = re.compile(r"[\w.+'-]+@([\w-]+(?:\.[\w-]+)+)", re.UNICODE)


def normalise_domain(domain: str) -> str:
    return (domain or "").strip().strip(".").lower()


def domain_of(address: str) -> str:
    """Domain of the (last) email address found in a header value."""
    matches = _ADDR.findall(address or "")
    return normalise_domain(matches[-1]) if matches else ""


def org_domain(domain: str) -> str:
    """Approximate organisational (registrable) domain, e.g. mail.example.co.uk -> example.co.uk."""
    domain = normalise_domain(domain)
    labels = domain.split(".")
    if len(labels) <= 2:
        return domain
    for n in (3, 2):  # longest built-in suffix first
        suffix = ".".join(labels[-n:])
        if suffix in MULTI_LABEL_SUFFIXES:
            return ".".join(labels[-(n + 1):]) if len(labels) > n else domain
    return ".".join(labels[-2:])


def same_org(a: str, b: str) -> bool:
    return bool(a and b) and org_domain(a) == org_domain(b)


def is_punycode(domain: str) -> bool:
    return any(label.startswith("xn--") for label in normalise_domain(domain).split("."))


def decode_idn(domain: str) -> str:
    out = []
    for label in normalise_domain(domain).split("."):
        if label.startswith("xn--"):
            try:
                label = label[4:].encode("ascii").decode("punycode")
            except (UnicodeError, ValueError):
                pass
        out.append(label)
    return ".".join(out)


def has_mixed_scripts(text: str) -> bool:
    scripts = set()
    for ch in text:
        if ch.isalpha():
            try:
                scripts.add(unicodedata.name(ch).split()[0])
            except ValueError:
                continue
    return len(scripts) > 1


def skeleton(label: str) -> str:
    """Collapse homoglyphs and common ASCII swaps so 'paypa1' and 'раypal' both become 'paypal'."""
    label = label.lower().translate(CONFUSABLES)
    for old, new in _ASCII_SWAPS:
        label = label.replace(old, new)
    return label


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def legit_brand_for(domain: str) -> str | None:
    """The brand that legitimately owns this domain, if any."""
    domain = normalise_domain(domain)
    for brand, (_, legit) in BRANDS.items():
        if any(domain == d or domain.endswith("." + d) for d in legit):
            return brand
    return None


def _brand_tokens():
    for brand, (names, legit) in BRANDS.items():
        for name in names:
            yield brand, name.replace(" ", ""), legit[0]


def lookalike_of(domain: str) -> str | None:
    """Return the brand domain this domain imitates, or None.

    Catches homoglyph/punycode domains, ASCII swaps (paypa1, rnicrosoft), small typos
    (arnazon) and a brand glued to bait words (paypal-secure-login).
    """
    domain = normalise_domain(domain)
    if not domain or legit_brand_for(domain):
        return None

    org = decode_idn(org_domain(domain))
    label = org.split(".")[0]
    norm = skeleton(label)
    tokens = [t for t in re.split(r"[-_.]", norm) if t]

    for brand, token, primary in _brand_tokens():
        if norm == token:
            return primary
        if token in tokens and len(tokens) > 1:
            return primary
        if len(token) >= 6:
            if any(levenshtein(t, token) <= (2 if len(token) >= 9 else 1) for t in tokens):
                return primary
            if token in norm and any(word in norm.replace(token, "") for word in BAIT_WORDS):
                return primary
            if any(token in t and t != token and any(w in t for w in BAIT_WORDS) for t in tokens):
                return primary
    return None


def brand_in(text: str) -> str | None:
    """Brand named in free text such as a display name ('PayPal Support')."""
    lowered = (text or "").lower()
    for brand, (names, _) in BRANDS.items():
        for name in names:
            if re.search(r"(?<![a-z0-9])" + re.escape(name) + r"(?![a-z0-9])", lowered):
                return brand
    return None


def tld(domain: str) -> str:
    return normalise_domain(domain).rsplit(".", 1)[-1]
