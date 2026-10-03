import io
import json
import unittest
import urllib.error

from phishkit.intel import VTClient, enrich, url_id
from phishkit.models import Severity


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def stats_body(malicious=0, suspicious=0):
    return json.dumps({"data": {"attributes": {"last_analysis_stats": {
        "malicious": malicious, "suspicious": suspicious, "harmless": 60, "undetected": 10}}}}).encode()


class FakeOpener:
    """Maps URL substrings to (status, body). Records requests."""

    def __init__(self, routes):
        self.routes = routes
        self.requests = []

    def __call__(self, request, timeout=None):
        self.requests.append(request)
        for needle, (status, body) in self.routes.items():
            if needle in request.full_url:
                if status != 200:
                    raise urllib.error.HTTPError(request.full_url, status, "err", {}, io.BytesIO(body))
                return FakeResponse(body)
        raise urllib.error.HTTPError(request.full_url, 404, "not found", {}, io.BytesIO(b"{}"))


SHA = "a" * 64


class VTClientTests(unittest.TestCase):
    def test_sends_api_key_header(self):
        opener = FakeOpener({SHA: (200, stats_body())})
        VTClient("secret-key", opener=opener).file_report(SHA)
        self.assertEqual(opener.requests[0].get_header("X-apikey"), "secret-key")

    def test_file_report_found(self):
        opener = FakeOpener({SHA: (200, stats_body(malicious=12))})
        report = VTClient("k", opener=opener).file_report(SHA)
        self.assertEqual(report["status"], "found")
        self.assertEqual(report["malicious"], 12)
        self.assertIn(SHA, report["link"])

    def test_not_found(self):
        report = VTClient("k", opener=FakeOpener({})).file_report(SHA)
        self.assertEqual(report["status"], "not_found")

    def test_url_id_is_unpadded_base64(self):
        self.assertEqual(url_id("http://example.com/"), "aHR0cDovL2V4YW1wbGUuY29tLw")


class EnrichTests(unittest.TestCase):
    def test_malicious_attachment_is_critical(self):
        attachments = [{"filename": "x.exe", "sha256": SHA}]
        client = VTClient("k", opener=FakeOpener({SHA: (200, stats_body(malicious=40))}))
        findings = enrich(attachments, [], client)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)
        self.assertEqual(attachments[0]["vt"]["malicious"], 40)

    def test_malicious_url_is_high_or_more(self):
        urls = [{"url": "http://evil.test/", "defanged": "hxxp://evil[.]test/", "flags": []}]
        client = VTClient("k", opener=FakeOpener({url_id("http://evil.test/"): (200, stats_body(malicious=2))}))
        findings = enrich([], urls, client)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertEqual(urls[0]["vt"]["malicious"], 2)

    def test_rate_limit_stops_and_reports_info(self):
        attachments = [{"filename": "a", "sha256": SHA}, {"filename": "b", "sha256": "b" * 64}]
        opener = FakeOpener({SHA: (429, b"{}")})
        findings = enrich(attachments, [], VTClient("k", opener=opener))
        self.assertEqual(len(opener.requests), 1)
        self.assertEqual(findings[0].severity, Severity.INFO)
        self.assertIn("rate limit", findings[0].title.lower())

    def test_clean_results_add_no_findings(self):
        attachments = [{"filename": "a", "sha256": SHA}]
        findings = enrich(attachments, [], VTClient("k", opener=FakeOpener({SHA: (200, stats_body())})))
        self.assertEqual(findings, [])
        self.assertEqual(attachments[0]["vt"]["malicious"], 0)

    def test_network_error_is_info(self):
        def broken(request, timeout=None):
            raise urllib.error.URLError("no route")
        findings = enrich([{"filename": "a", "sha256": SHA}], [], VTClient("k", opener=broken))
        self.assertEqual(findings[0].severity, Severity.INFO)


if __name__ == "__main__":
    unittest.main()
