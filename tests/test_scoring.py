import unittest

from phishkit.analyzer import analyze
from phishkit.models import Finding, Severity
from phishkit.scoring import score
from tests.helpers import make_eml


def f(sev):
    return Finding("x", sev, "t")


class ScoringTests(unittest.TestCase):
    def test_empty_is_clean(self):
        self.assertEqual(score([]), (0, "Clean"))

    def test_weights_sum(self):
        self.assertEqual(score([f(Severity.LOW), f(Severity.MEDIUM)]), (20, "Suspicious"))

    def test_thresholds(self):
        self.assertEqual(score([f(Severity.MEDIUM)])[1], "Clean")           # 15
        self.assertEqual(score([f(Severity.HIGH)])[1], "Suspicious")        # 30
        self.assertEqual(score([f(Severity.CRITICAL)])[1], "Likely phishing")  # 50

    def test_capped_at_100(self):
        self.assertEqual(score([f(Severity.CRITICAL)] * 5), (100, "Likely phishing"))

    def test_info_scores_zero(self):
        self.assertEqual(score([f(Severity.INFO)] * 10), (0, "Clean"))


class AnalyzerTests(unittest.TestCase):
    def test_report_has_all_sections(self):
        raw = make_eml(html='<a href="http://192.0.2.1/login">https://paypal.com</a>',
                       attachments=[("a.pdf", b"%PDF-1.4", "application", "pdf")])
        report = analyze(raw)
        d = report.to_dict()
        for key in ("summary", "auth", "senders", "urls", "attachments", "received", "findings", "score", "verdict"):
            self.assertIn(key, d)
        self.assertEqual(d["summary"]["subject"], "Hello")
        self.assertEqual(len(d["attachments"]), 1)
        self.assertGreaterEqual(report.score, 30)

    def test_findings_sorted_most_severe_first(self):
        raw = make_eml(headers={"Reply-To": "x@gmail.com"}, html='<a href="http://192.0.2.1/">x</a>')
        weights = [int(x.severity) for x in analyze(raw).findings]
        self.assertEqual(weights, sorted(weights, reverse=True))

    def test_vt_without_key_adds_info(self):
        import os
        old = os.environ.pop("VT_API_KEY", None)
        try:
            report = analyze(make_eml(), vt=True)
        finally:
            if old is not None:
                os.environ["VT_API_KEY"] = old
        self.assertIn("VirusTotal skipped", [x.title for x in report.findings])

    def test_garbage_input_still_produces_report(self):
        report = analyze(b"\x00\xff garbage")
        self.assertIsNotNone(report.verdict)


if __name__ == "__main__":
    unittest.main()
