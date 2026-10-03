"""Run every analysis module over one email and assemble the Report."""

from __future__ import annotations

from dataclasses import asdict

from .attachments import analyze_attachments
from .auth import analyze_auth
from .intel import VTClient, enrich
from .models import Finding, Report, Severity
from .parser import parse_email
from .scoring import score
from .senders import analyze_senders
from .urls import analyze_urls

PREVIEW_TEXT_CHARS = 5000
PREVIEW_HTML_CHARS = 20000


def analyze(raw: bytes, live: bool = False, vt: bool = False, resolver=None,
            vt_client: VTClient | None = None) -> Report:
    email = parse_email(raw)
    findings: list[Finding] = []

    if email.parse_errors:
        findings.append(Finding(
            "parsing", Severity.INFO, "Email structure has defects",
            "The message is malformed in places. Attackers sometimes break MIME structure on "
            "purpose to confuse filters; results below are best-effort.",
            "; ".join(email.parse_errors[:5]),
        ))

    def guarded(name, func, *args, empty, **kwargs):
        """Run one analysis module; an unexpected error becomes a finding, never a crash."""
        try:
            return func(*args, **kwargs)
        except Exception as exc:  # hostile input must not take the whole report down
            findings.append(Finding(
                "parsing", Severity.INFO, "Part of the analysis failed",
                f"The {name} check could not process this email, so its results are missing. "
                "Review that part manually.", f"{type(exc).__name__}: {exc}"[:300],
            ))
            return empty, []

    auth, auth_findings = guarded("authentication", analyze_auth, email, live=live, resolver=resolver,
                                  empty={"recorded": {}, "authserv_id": "", "dkim_domains": [],
                                         "other_headers": [], "live": None})
    senders, sender_findings = guarded("sender", analyze_senders, email, empty={"mismatches": []})
    urls, url_findings = guarded("link", analyze_urls, email, empty=[])
    attachments, attachment_findings = guarded("attachment", analyze_attachments, email, empty=[])
    findings += auth_findings + sender_findings + url_findings + attachment_findings

    if vt:
        client = vt_client or VTClient.from_env()
        if client is None:
            findings.append(Finding("threat-intel", Severity.INFO, "VirusTotal skipped",
                                    "Set the VT_API_KEY environment variable to enable reputation lookups."))
        else:
            findings += guarded("VirusTotal", lambda: (None, enrich(attachments, urls, client)), empty=None)[1]

    findings.sort(key=lambda f: int(f.severity), reverse=True)
    total, verdict = score(findings)

    return Report(
        summary={
            "subject": email.subject,
            "from": email.from_,
            "to": email.to,
            "date": email.date,
            "message_id": email.message_id,
            "options": {"live": live, "vt": vt},
        },
        auth=auth,
        senders=senders,
        urls=urls,
        attachments=attachments,
        received=[asdict(h) for h in email.received],
        body_preview={
            "text": email.text_body[:PREVIEW_TEXT_CHARS],
            "html_source": email.html_body[:PREVIEW_HTML_CHARS],
            "truncated": len(email.text_body) > PREVIEW_TEXT_CHARS or len(email.html_body) > PREVIEW_HTML_CHARS,
        },
        findings=findings,
        score=total,
        verdict=verdict,
    )
