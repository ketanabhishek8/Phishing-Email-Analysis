"""Render a Report as readable terminal text."""

from __future__ import annotations

import textwrap

from .models import Report

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


def render_text(report: Report, color: bool = True) -> str:
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

    bar = "█" * (report.score // 5) + "░" * (20 - report.score // 5)
    lines.append(p("PhishKit report", "bold"))
    lines.append(f"Verdict: {p(report.verdict, report.verdict)}   Risk score: {report.score}/100  {bar}")

    heading("Summary")
    s = report.summary
    for label, key in (("Subject", "subject"), ("From", "from"), ("To", "to"), ("Date", "date"),
                       ("Message-ID", "message_id")):
        field(label, s.get(key, ""))

    heading("Authentication")
    rec = report.auth.get("recorded", {})
    if report.auth.get("authserv_id"):
        field("Checked by", report.auth["authserv_id"])
    for method in ("spf", "dkim", "dmarc"):
        entry = rec.get(method, {})
        result = entry.get("result", "none")
        lines.append(f"  {method.upper():<13} {p(result, _result_style(result))}  {p(entry.get('detail', ''), 'dim')}")
    live = report.auth.get("live")
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
        policy_text = f" policy p={pol['p']}" if pol else ""
        lines.append(f"  {'DMARC':<13} {p(d['result'], _result_style(d['result']))}  "
                     f"{p(d['detail'] + policy_text, 'dim')}")

    heading("Sender")
    sd = report.senders
    field("From", f"{sd.get('from_name', '')} <{sd.get('from_address', '')}>".strip())
    field("Reply-To", sd.get("reply_to", ""))
    field("Return-Path", sd.get("return_path", ""))
    field("Sender", sd.get("sender", ""))
    if sd.get("lookalike"):
        field("Imitates", sd["lookalike"])

    heading(f"URLs ({len(report.urls)})")
    if not report.urls:
        lines.append(p("  none", "dim"))
    for u in report.urls:
        flags = ", ".join(u.get("flags") or []) or "no flags"
        lines.append(f"  • {u['defanged']}")
        lines.append(p(f"      {flags}", "dim" if not u.get("flags") else "medium"))

    heading(f"Attachments ({len(report.attachments)})")
    if not report.attachments:
        lines.append(p("  none", "dim"))
    for a in report.attachments:
        lines.append(f"  • {a['filename']}  ({a['size']} bytes, detected: {a['detected_type']})")
        lines.append(f"      MD5     {a['md5']}")
        lines.append(f"      SHA1    {a['sha1']}")
        lines.append(f"      SHA256  {a['sha256']}")
        if a.get("flags"):
            lines.append(p(f"      flags: {', '.join(a['flags'])}", "medium"))
        if a.get("vt", {}).get("status") == "found":
            vt = a["vt"]
            lines.append(f"      VirusTotal: {vt['malicious']} malicious / {vt['suspicious']} suspicious")

    heading(f"Findings ({len(report.findings)})")
    if not report.findings:
        lines.append(p("  nothing suspicious found", "dim"))
    for f in report.findings:
        label = f.severity.label.upper()
        lines.append(f"  {p(f'[{label}]', f.severity.label)} {p(f.title, 'bold')}")
        for w in textwrap.wrap(f.detail, WIDTH - 6):
            lines.append(f"      {w}")
        if f.evidence:
            for w in textwrap.wrap(f.evidence, WIDTH - 6):
                lines.append(p(f"      {w}", "dim"))

    lines.append("")
    return "\n".join(lines)
