"""Optional VirusTotal reputation lookups for attachment hashes and URLs.

Only used when the analyst opts in (--vt / the web checkbox) and VT_API_KEY is set.
Only hashes and URLs are sent, never the email or attachment content.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request

from .models import Finding, Severity

CATEGORY = "threat-intel"
API = "https://www.virustotal.com/api/v3"
GUI = "https://www.virustotal.com/gui"
MAX_URL_LOOKUPS = 10


class VTError(Exception):
    def __init__(self, kind: str, message: str = ""):
        super().__init__(message or kind)
        self.kind = kind  # rate_limit | auth | network | error


def url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


class VTClient:
    def __init__(self, api_key: str, opener=urllib.request.urlopen, timeout: float = 10.0):
        self.api_key = api_key
        self.opener = opener
        self.timeout = timeout

    @classmethod
    def from_env(cls) -> "VTClient | None":
        key = os.environ.get("VT_API_KEY", "").strip()
        return cls(key) if key else None

    def _get(self, path: str, link: str) -> dict:
        request = urllib.request.Request(f"{API}/{path}", headers={"x-apikey": self.api_key,
                                                                   "accept": "application/json"})
        try:
            with self.opener(request, timeout=self.timeout) as response:
                body = json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return {"status": "not_found", "link": link}
            if exc.code == 429:
                raise VTError("rate_limit", "VirusTotal rate limit reached") from None
            if exc.code in (401, 403):
                raise VTError("auth", "VirusTotal rejected the API key") from None
            raise VTError("error", f"VirusTotal returned HTTP {exc.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise VTError("network", f"could not reach VirusTotal: {exc}") from None
        except json.JSONDecodeError:
            raise VTError("error", "VirusTotal returned invalid JSON") from None

        stats = body.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "status": "found",
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "harmless": int(stats.get("harmless", 0)),
            "undetected": int(stats.get("undetected", 0)),
            "link": link,
        }

    def file_report(self, sha256: str) -> dict:
        return self._get(f"files/{sha256}", f"{GUI}/file/{sha256}")

    def url_report(self, url: str) -> dict:
        uid = url_id(url)
        return self._get(f"urls/{uid}", f"{GUI}/url/{uid}")


def _verdict(report: dict, subject: str, evidence: str) -> Finding | None:
    if report.get("status") != "found":
        return None
    malicious, suspicious = report["malicious"], report["suspicious"]
    if malicious >= 3:
        severity = Severity.CRITICAL
    elif malicious >= 1:
        severity = Severity.HIGH
    elif suspicious >= 1:
        severity = Severity.MEDIUM
    else:
        return None
    return Finding(CATEGORY, severity, f"VirusTotal flags {subject}",
                   f"{malicious} engines report malicious and {suspicious} suspicious.", evidence)


def enrich(attachments: list[dict], urls: list[dict], client: VTClient) -> list[Finding]:
    """Look up attachments first, then URLs (flagged ones first). Mutates entries with a 'vt' key."""
    findings: list[Finding] = []
    lookable_urls = [u for u in urls if u["url"].lower().startswith(("http://", "https://"))]
    lookable_urls.sort(key=lambda u: not u.get("flags"))
    jobs = [("attachment", a, lambda a=a: client.file_report(a["sha256"]), a["filename"]) for a in attachments]
    jobs += [("URL", u, lambda u=u: client.url_report(u["url"]), u.get("defanged", u["url"]))
             for u in lookable_urls[:MAX_URL_LOOKUPS]]

    for kind, entry, lookup, evidence in jobs:
        try:
            report = lookup()
        except VTError as exc:
            title = ("VirusTotal rate limit reached" if exc.kind == "rate_limit"
                     else "VirusTotal lookup failed")
            findings.append(Finding(CATEGORY, Severity.INFO, title,
                                    f"{exc}. Remaining lookups were skipped; the free API allows "
                                    "4 requests per minute.", evidence))
            break
        entry["vt"] = report
        finding = _verdict(report, f"this {kind}", evidence)
        if finding:
            findings.append(finding)
    return findings
