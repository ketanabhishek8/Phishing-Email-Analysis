"""SPF, DKIM and DMARC: what the receiving server recorded, plus optional live re-checks."""

from __future__ import annotations

import email as email_lib
import ipaddress
import logging
import re
from email import policy as email_policy

from . import dmarc, spf
from .dnsutil import DNSError, default_resolver
from .domains import domain_of
from .models import Finding, Severity
from .parser import ParsedEmail

METHODS = ("spf", "dkim", "dmarc")
CATEGORY = "authentication"

NOT_RECORDED = "not recorded by the receiving server"


def _split_top_level(value: str) -> tuple[list[str], list[list[str]]]:
    """Split on ';' outside comments and quotes. Returns the segments and, for each
    segment, the comments it contained (comments are removed from the segment)."""
    segments, comments = [], []
    current, current_comments, comment = [], [], []
    depth, quoted = 0, False
    for ch in value:
        if quoted:
            current.append(ch)
            quoted = ch != '"'
        elif depth:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    current_comments.append("".join(comment).strip())
                    comment = []
                    continue
            comment.append(ch)
        elif ch == "(":
            depth = 1
        elif ch == '"':
            quoted = True
            current.append(ch)
        elif ch == ";":
            segments.append("".join(current).strip())
            comments.append(current_comments)
            current, current_comments = [], []
        else:
            current.append(ch)
    segments.append("".join(current).strip())
    comments.append(current_comments)
    return segments, comments


def parse_auth_results(value: str) -> dict:
    """Parse an Authentication-Results header (RFC 8601)."""
    value = " ".join((value or "").split())
    segments, comments = _split_top_level(value)
    # ARC-Authentication-Results starts with an instance tag: "i=1; authserv-id; ..."
    if segments and re.fullmatch(r"i=\d+", segments[0]):
        segments, comments = segments[1:], comments[1:]
    # RFC 8601 starts with the authserv-id, but Microsoft 365 omits it and begins
    # straight with "spf=...". Detect that by the method=result shape of the first token.
    first = segments[0].split()[0] if segments and segments[0] else ""
    if re.fullmatch(r"[a-z][a-z0-9-]*(/[0-9]+)?=[a-z]+", first, re.I):
        authserv_id, start = "", 0
    else:
        authserv_id, start = first, 1
    results = []
    for segment, seg_comments in zip(segments[start:], comments[start:]):
        tokens = segment.split()
        if not tokens or "=" not in tokens[0]:
            continue  # "none" or garbage
        method, _, result = tokens[0].partition("=")
        props = {}
        for token in tokens[1:]:
            key, sep, val = token.partition("=")
            if sep:
                props[key.lower()] = val.strip('"')
        results.append({
            "method": method.lower().split("/")[0],
            "result": result.lower(),
            "props": props,
            "comment": "; ".join(seg_comments),
        })
    return {"authserv_id": authserv_id, "results": results}


def _dkim_domain(props: dict) -> str:
    domain = props.get("header.d") or props.get("header.i", "").lstrip("@").split("@")[-1]
    domain = domain.lower()
    return "" if domain in ("none", "") else domain


def _summarise(parsed: dict, source: str) -> dict:
    """Collapse parsed results into one verdict per method."""
    summary = {}
    by_method: dict[str, list[dict]] = {}
    for r in parsed["results"]:
        by_method.setdefault(r["method"], []).append(r)

    for method in METHODS:
        entries = by_method.get(method)
        if not entries:
            continue
        if method == "dkim":
            # One email can carry several signatures; any passing one counts.
            passing = [e for e in entries if e["result"] == "pass"]
            chosen = passing[0] if passing else entries[0]
            detail = ", ".join(
                f"{_dkim_domain(e['props'])}={e['result']}" if _dkim_domain(e["props"])
                else (e["comment"] or e["result"])
                for e in entries
            )
        else:
            chosen = entries[0]
            parts = [f"{k}={v}" for k, v in chosen["props"].items()]
            if chosen["comment"]:
                parts.append(f"({chosen['comment']})")
            detail = " ".join(parts)
        summary[method] = {"result": chosen["result"], "detail": detail, "source": source}
    return summary


def _received_spf(value: str) -> dict:
    result = (value.split() or ["none"])[0].lower()
    return {"result": result, "detail": value, "source": "Received-SPF"}


_SEVERITY = {
    "spf": {"fail": (Severity.HIGH, "SPF failed"), "softfail": (Severity.MEDIUM, "SPF softfail"),
            "none": (Severity.LOW, "No SPF record"), "neutral": (Severity.LOW, "SPF neutral"),
            "permerror": (Severity.LOW, "SPF permanent error"), "temperror": (Severity.LOW, "SPF temporary error")},
    "dkim": {"fail": (Severity.MEDIUM, "DKIM signature failed"), "none": (Severity.LOW, "Email is not DKIM-signed"),
             "neutral": (Severity.LOW, "DKIM neutral"), "permerror": (Severity.LOW, "DKIM permanent error"),
             "temperror": (Severity.LOW, "DKIM temporary error"), "policy": (Severity.LOW, "DKIM policy result")},
    "dmarc": {"fail": (Severity.HIGH, "DMARC failed"), "none": (Severity.LOW, "No DMARC policy"),
              "permerror": (Severity.LOW, "DMARC permanent error"), "temperror": (Severity.LOW, "DMARC temporary error")},
}

_EXPLAIN = {
    "spf": "SPF checks whether the sending server's IP is authorised by the envelope sender's domain.",
    "dkim": "DKIM is a cryptographic signature proving the domain in d= sent the message unaltered.",
    "dmarc": "DMARC requires SPF or DKIM to pass for a domain aligned with the visible From address.",
}


def analyze_recorded(email: ParsedEmail) -> tuple[dict, list[Finding]]:
    findings: list[Finding] = []
    ar_headers = email.get_all("Authentication-Results")
    arc_headers = email.get_all("ARC-Authentication-Results")

    recorded: dict = {}
    authserv_id = ""
    dkim_domains: list[str] = []
    parsed = None
    if ar_headers:
        parsed = parse_auth_results(ar_headers[0])
        recorded = _summarise(parsed, "Authentication-Results")
    elif arc_headers:
        # Highest ARC instance = most recent hop that sealed the results.
        def instance(v):
            m = re.match(r"\s*i=(\d+)", v)
            return int(m.group(1)) if m else 0
        parsed = parse_auth_results(max(arc_headers, key=instance))
        recorded = _summarise(parsed, "ARC-Authentication-Results")
    if parsed:
        authserv_id = parsed["authserv_id"]
        dkim_domains = sorted({_dkim_domain(r["props"]) for r in parsed["results"]
                               if r["method"] == "dkim" and _dkim_domain(r["props"])})

    received_spf = email.get("Received-SPF")
    if "spf" not in recorded and received_spf:
        recorded["spf"] = _received_spf(received_spf)

    nothing_recorded = not recorded
    for method in METHODS:
        recorded.setdefault(method, {"result": "none", "detail": NOT_RECORDED, "source": ""})

    if nothing_recorded:
        findings.append(Finding(
            CATEGORY, Severity.INFO, "No authentication results recorded",
            "The email has no Authentication-Results or Received-SPF header, so the receiving "
            "server's SPF/DKIM/DMARC verdicts are unknown. This is normal for emails saved from "
            "some clients or forwarded as attachments; run with live checks to verify via DNS.",
        ))
    else:
        for method in METHODS:
            entry = recorded[method]
            if entry["detail"] == NOT_RECORDED:
                continue
            rule = _SEVERITY[method].get(entry["result"])
            if rule:
                severity, title = rule
                findings.append(Finding(CATEGORY, severity, title, _EXPLAIN[method], entry["detail"]))

    other = ar_headers[1:]
    if other:
        findings.append(Finding(
            CATEGORY, Severity.INFO, f"{len(other)} older Authentication-Results header(s) ignored",
            "Only the topmost header, added by the final receiving server, is trusted. "
            "Lower headers could have been written by the sender and forged.",
        ))

    section = {
        "recorded": recorded,
        "authserv_id": authserv_id,
        "dkim_domains": dkim_domains,
        "other_headers": other + arc_headers,
        "live": None,
    }
    return section, findings


# ---------------------------------------------------------------- live checks

_QUIET = logging.getLogger("phishkit.dkim")
_QUIET.addHandler(logging.NullHandler())
_QUIET.propagate = False


def _tags(value: str) -> dict:
    tags = {}
    for part in "".join(value.split()).split(";"):
        key, sep, val = part.partition("=")
        if sep:
            tags[key.lower()] = val
    return tags


def verify_dkim(raw: bytes, resolver) -> list[dict]:
    """Cryptographically re-verify every DKIM-Signature against the signer's DNS key."""
    import dkim

    msg = email_lib.message_from_bytes(raw, policy=email_policy.compat32)
    signatures = msg.get_all("DKIM-Signature") or []
    results = []
    for idx, value in enumerate(signatures):
        tags = _tags(str(value))
        domain, selector = tags.get("d", "").lower(), tags.get("s", "")
        entry = {"domain": domain, "selector": selector, "result": "", "detail": ""}
        results.append(entry)
        if not domain or not selector:
            entry.update(result="permerror", detail="signature is missing d= or s=")
            continue
        key_name = f"{selector}._domainkey.{domain}"
        try:
            key_record = "".join(resolver.txt(key_name))
        except DNSError as exc:
            if exc.kind == "nxdomain":
                entry.update(result="key unavailable",
                             detail=f"no public key at {key_name}; the sender may have rotated it since the email was sent")
            else:
                entry.update(result="temperror", detail=f"DNS {exc.kind} fetching {key_name}")
            continue
        try:
            ok = dkim.DKIM(raw, logger=_QUIET).verify(
                idx=idx, dnsfunc=lambda name, timeout=5: key_record.encode()
            )
        except dkim.KeyFormatError as exc:
            entry.update(result="key unavailable", detail=f"public key at {key_name} is unusable: {exc}")
            continue
        except dkim.DKIMException as exc:
            if "body hash mismatch" in str(exc):
                entry.update(result="fail", detail="body hash mismatch: the body was altered after signing")
            else:
                entry.update(result="permerror", detail=f"malformed signature: {exc}")
            continue
        if ok:
            entry.update(result="pass", detail=f"signature verified with key {key_name}")
        else:
            entry.update(result="fail", detail="signature does not match: headers or body were altered, or it was forged")
    return results


# Networks that belong to the recipient's own infrastructure, never the true sender.
_INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "100.64.0.0/10", "0.0.0.0/8", "::1/128", "fc00::/7", "fe80::/10", "::/128",
)]


def _public_ip(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return ""
    if any(ip.version == net.version and ip in net for net in _INTERNAL_NETS):
        return ""
    return str(ip)


def originating_ip(email: ParsedEmail) -> str:
    """Best guess at the IP that handed the email to the recipient's infrastructure."""
    received_spf = email.get("Received-SPF") or ""
    match = re.search(r"client-ip=([0-9A-Fa-f:.]+)", received_spf)
    if match and _public_ip(match.group(1).rstrip(";")):
        return _public_ip(match.group(1).rstrip(";"))
    for ar in email.get_all("Authentication-Results")[:1]:
        match = re.search(r"designates ([0-9A-Fa-f:.]+) as permitted", ar)
        if match and _public_ip(match.group(1)):
            return _public_ip(match.group(1))
    for hop in email.received:
        if _public_ip(hop.ip):
            return _public_ip(hop.ip)
    return ""


def _is_recorded(section: dict, method: str) -> bool:
    return section["recorded"][method]["detail"] != NOT_RECORDED


def analyze_live(email: ParsedEmail, section: dict, resolver) -> tuple[dict, list[Finding]]:
    findings: list[Finding] = []
    from_domain = domain_of(email.from_)
    spf_domain = domain_of(email.get("Return-Path") or "") or from_domain
    ip = originating_ip(email)

    spf_result, spf_detail = spf.check_spf(ip, spf_domain, resolver)
    dkim_results = verify_dkim(email.raw, resolver)
    passing_dkim = [r["domain"] for r in dkim_results if r["result"] == "pass"]

    try:
        policy = dmarc.fetch_policy(from_domain, resolver)
        policy_error = None
    except DNSError as exc:
        policy, policy_error = None, exc.kind

    align = dmarc.alignment(
        from_domain,
        spf_domain if spf_result == "pass" else "",
        passing_dkim,
        (policy or {}).get("adkim", "r"),
        (policy or {}).get("aspf", "r"),
    )
    align["spf_domain"] = spf_domain

    if policy_error:
        dmarc_result, dmarc_detail = "temperror", f"DNS {policy_error} looking up _dmarc.{from_domain}"
    elif policy is None:
        dmarc_result, dmarc_detail = "none", f"{from_domain or 'the From domain'} publishes no DMARC record"
    elif align["spf_aligned"] or align["dkim_aligned"]:
        dmarc_result = "pass"
        dmarc_detail = "aligned " + " and ".join(
            k for k, v in (("SPF", align["spf_aligned"]), ("DKIM", align["dkim_aligned"])) if v
        )
    else:
        dmarc_result = "fail"
        dmarc_detail = (f"neither SPF ({spf_domain}: {spf_result}) nor DKIM "
                        f"({', '.join(passing_dkim) or 'no valid signature'}) passed aligned with {from_domain}")

    if not dkim_results:
        dkim_summary = "none"
    elif passing_dkim:
        dkim_summary = "pass"
    elif any(r["result"] == "fail" for r in dkim_results):
        dkim_summary = "fail"
    else:
        dkim_summary = dkim_results[0]["result"]

    live = {
        "ip": ip,
        "spf": {"result": spf_result, "detail": spf_detail, "domain": spf_domain},
        "dkim": dkim_results,
        "dkim_result": dkim_summary,
        "dmarc": {"result": dmarc_result, "detail": dmarc_detail, "policy": policy},
        "alignment": align,
    }

    # Score a live result only when the receiving server recorded nothing for that
    # method; otherwise the recorded verdict already counted and we just note a disagreement.
    for method, result, detail in (("spf", spf_result, spf_detail),
                                   ("dkim", dkim_summary, "; ".join(r["detail"] for r in dkim_results)),
                                   ("dmarc", dmarc_result, dmarc_detail)):
        if _is_recorded(section, method):
            recorded = section["recorded"][method]["result"]
            if recorded != result:
                findings.append(Finding(
                    CATEGORY, Severity.INFO, f"Live {method.upper()} result differs from recorded",
                    f"The receiving server recorded '{recorded}' but re-checking now gives '{result}'. "
                    "DNS may have changed since delivery.", detail,
                ))
            continue
        if method == "dkim" and result == "key unavailable":
            findings.append(Finding(CATEGORY, Severity.INFO, "DKIM key unavailable (live check)",
                                    "The signing key is no longer published, so the signature cannot be re-verified.",
                                    detail))
            continue
        rule = _SEVERITY[method].get(result)
        if rule:
            severity, title = rule
            findings.append(Finding(CATEGORY, severity, f"{title} (live check)", _EXPLAIN[method], detail))

    if policy and policy["p"] == "none" and dmarc_result != "fail":
        findings.append(Finding(
            CATEGORY, Severity.LOW, "DMARC policy is monitor-only (p=none)",
            f"{policy['domain']} asks receivers to take no action on DMARC failures, so spoofed "
            "mail using this domain is still delivered.", policy["record"],
        ))
    return live, findings


def analyze_auth(email: ParsedEmail, live: bool = False, resolver=None) -> tuple[dict, list[Finding]]:
    section, findings = analyze_recorded(email)
    if live:
        live_section, live_findings = analyze_live(email, section, resolver or default_resolver())
        section["live"] = live_section
        findings.extend(live_findings)
    return section, findings
