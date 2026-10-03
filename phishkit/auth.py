"""SPF, DKIM and DMARC: what the receiving server recorded, plus optional live re-checks."""

from __future__ import annotations

import re

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
    authserv_id = segments[0].split()[0] if segments and segments[0] else ""
    results = []
    for segment, seg_comments in zip(segments[1:], comments[1:]):
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
    return domain.lower()


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
                f"{_dkim_domain(e['props']) or '?'}={e['result']}" for e in entries
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


def analyze_auth(email: ParsedEmail, live: bool = False, resolver=None) -> tuple[dict, list[Finding]]:
    section, findings = analyze_recorded(email)
    return section, findings
