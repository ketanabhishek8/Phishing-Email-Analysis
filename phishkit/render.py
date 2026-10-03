"""Render a Report as readable terminal text."""

from __future__ import annotations

import textwrap

from .models import Report
from .textsafe import for_terminal

_COLORS = {
    "critical": "\x1b[1;97;41m", "high": "\x1b[1;31m", "medium": "\x1b[33m", "low": "\x1b[36m",
    "info": "\x1b[2m", "bold": "\x1b[1m", "dim": "\x1b[2m", "reset": "\x1b[0m",
    "Clean": "\x1b[1;32m", "Suspicious": "\x1b[1;33m", "Likely phishing": "\x1b[1;31m",
    "pass": "\x1b[32m", "fail": "\x1b[31m",
}
WIDTH = 78


class _Painter:
    def __init__(self, color: bool):
        self.color = color

    def __call__(self, text: str, style: str) -> str:
        if not self.color or style not in _COLORS:
            return text
        return f"{_COLORS[style]}{text}{_COLORS['reset']}"


def _result_style(result: str) -> str:
    return "pass" if result == "pass" else "fail" if result in ("fail", "softfail") else "dim"


def _sanitize(value):
    """Recursively neutralise control and invisible characters in email-derived data."""
    if isinstance(value, str):
        return for_terminal(value)
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    return value


class _Finding:
    def __init__(self, d: dict):
        self.title, self.detail, self.evidence = d["title"], d["detail"], d["evidence"]
        self.label = d["severity"]


def render_text(report: Report, color: bool = True) -> str:
    """Render the report. Every string from the email is sanitised first, so escape
    sequences or bidi tricks inside the email cannot rewrite the analyst's terminal."""
    data = _sanitize(report.to_dict())
    p = _Painter(color)
    lines: list[str] = []

    def heading(title: str):
        lines.append("")
        lines.append(p(f"── {title} " + "─" * max(0, WIDTH - len(title) - 4), "bold"))

    def field(label: str, value: str):
        if value:
            wrapped = textwrap.wrap(str(value), WIDTH - 16) or [""]
            lines.append(f"  {label:<13} {wrapped[0]}")
            lines.extend(f"  {'':<13} {w}" for w in wrapped[1:])

    score, verdict = data["score"], data["verdict"]
    bar = "█" * (score // 5) + "░" * (20 - score // 5)
    lines.append(p("PhishKit report", "bold"))
    lines.append(f"Verdict: {p(verdict, verdict)}   Risk score: {score}/100  {bar}")

    heading("Summary")
    s = data["summary"]
    for label, key in (("Subject", "subject"), ("From", "from"), ("To", "to"), ("Date", "date"),
                       ("Message-ID", "message_id")):
        field(label, s.get(key, ""))

    heading("Authentication")
    rec = data["auth"].get("recorded", {})
    if data["auth"].get("authserv_id"):
        field("Checked by", data["auth"]["authserv_id"])
    for method in ("spf", "dkim", "dmarc"):
        entry = rec.get(method, {})
        result = entry.get("result", "none")
        lines.append(f"  {method.upper():<13} {p(result, _result_style(result))}  {p(entry.get('detail', ''), 'dim')}")
    live = data["auth"].get("live")
    if live:
        lines.append(p("  Live DNS re-check:", "bold"))
        field("Origin IP", live.get("ip") or "unknown")
        lines.append(f"  {'SPF':<13} {p(live['spf']['result'], _result_style(live['spf']['result']))}  "
                     f"{p(live['spf']['detail'], 'dim')}")
        for sig in live.get("dkim") or []:
            lines.append(f"  {'DKIM':<13} {p(sig['result'], _result_style(sig['result']))}  "
                         f"{p(sig['domain'] + ' (' + sig['selector'] + '): ' + sig['detail'], 'dim')}")
        if not live.get("dkim"):
            lines.append(f"  {'DKIM':<13} {p('none', 'dim')}  {p('no DKIM-Signature header', 'dim')}")
        d = live["dmarc"]
        pol = d.get("policy") or {}
        policy_text = f" policy {'sp' if pol.get('inherited') else 'p'}={pol.get('effective', pol['p'])}" if pol else ""
        lines.append(f"  {'DMARC':<13} {p(d['result'], _result_style(d['result']))}  "
                     f"{p(d['detail'] + policy_text, 'dim')}")

    heading("Sender")
    sd = data["senders"]
    field("From", f"{sd.get('from_name', '')} <{sd.get('from_address', '')}>".strip())
    field("Reply-To", sd.get("reply_to", ""))
    field("Return-Path", sd.get("return_path", ""))
    field("Sender", sd.get("sender", ""))
    if sd.get("lookalike"):
        field("Imitates", sd["lookalike"])

    heading(f"URLs ({len(data["urls"])})")
    if not data["urls"]:
        lines.append(p("  none", "dim"))
    for u in data["urls"]:
        flags = ", ".join(u.get("flags") or []) or "no flags"
        lines.append(f"  • {u['defanged']}")
        lines.append(p(f"      {flags}", "dim" if not u.get("flags") else "medium"))

    heading(f"Attachments ({len(data["attachments"])})")
    if not data["attachments"]:
        lines.append(p("  none", "dim"))
    for a in data["attachments"]:
        lines.append(f"  • {a['filename']}  ({a['size']} bytes, detected: {a['detected_type']})")
        lines.append(f"      MD5     {a['md5']}")
        lines.append(f"      SHA1    {a['sha1']}")
        lines.append(f"      SHA256  {a['sha256']}")
        if a.get("flags"):
            lines.append(p(f"      flags: {', '.join(a['flags'])}", "medium"))
        if a.get("vt", {}).get("status") == "found":
            vt = a["vt"]
            lines.append(f"      VirusTotal: {vt['malicious']} malicious / {vt['suspicious']} suspicious")

    findings = [_Finding(f) for f in data["findings"]]
    heading(f"Findings ({len(findings)})")
    if not findings:
        lines.append(p("  nothing suspicious found", "dim"))
    for f in findings:
        label = f.label.upper()
        lines.append(f"  {p(f'[{label}]', f.label)} {p(f.title, 'bold')}")
        for w in textwrap.wrap(f.detail, WIDTH - 6):
            lines.append(f"      {w}")
        if f.evidence:
            for w in textwrap.wrap(f.evidence, WIDTH - 6):
                lines.append(p(f"      {w}", "dim"))

    lines.append("")
    return "\n".join(lines)
