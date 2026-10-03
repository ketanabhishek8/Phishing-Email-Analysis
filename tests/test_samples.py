"""End-to-end: every sample email produces its expected verdict and signature findings."""

import unittest
from pathlib import Path

from phishkit.analyzer import analyze

SAMPLES = Path(__file__).resolve().parent.parent / "samples"

EXPECTED = {
    "01-m365-credential-harvest.eml": ("Likely phishing", [
        "Lookalike sender domain", "Link text shows a different domain",
        "Link hosted on a free hosting or tunnelling platform"]),
    "02-paypal-spoof-punycode.eml": ("Likely phishing", [
        "SPF failed", "DMARC failed", "Punycode (internationalised) domain in link",
        "Link points to a raw IP address", "Brand name used in an unrelated domain",
        "URL shortener hides the destination"]),
    "03-invoice-macro-attachment.eml": ("Likely phishing", [
        "Office document contains macros", "Risky attachment type", "Reply-To differs from From"]),
    "04-bec-ceo-fraud.eml": ("Likely phishing", [
        "Reply-To differs from From", "Display name contains a different email address"]),
    "05-html-smuggling.eml": ("Likely phishing", [
        "HTML smuggling attachment", "Lookalike sender domain"]),
    "06-legit-newsletter.eml": ("Clean", []),
}


class SampleTests(unittest.TestCase):
    def test_every_sample_is_covered(self):
        self.assertEqual(sorted(p.name for p in SAMPLES.glob("*.eml")), sorted(EXPECTED))

    def test_samples(self):
        for name, (verdict, titles) in EXPECTED.items():
            with self.subTest(sample=name):
                report = analyze((SAMPLES / name).read_bytes())
                self.assertEqual(report.verdict, verdict)
                found = {f.title for f in report.findings}
                for title in titles:
                    self.assertIn(title, found)

    def test_legit_newsletter_has_no_scored_findings(self):
        report = analyze((SAMPLES / "06-legit-newsletter.eml").read_bytes())
        self.assertEqual(report.score, 0)

    def test_macro_attachment_hash_is_stable(self):
        report = analyze((SAMPLES / "03-invoice-macro-attachment.eml").read_bytes())
        self.assertEqual(len(report.attachments[0]["sha256"]), 64)
        again = analyze((SAMPLES / "03-invoice-macro-attachment.eml").read_bytes())
        self.assertEqual(report.attachments[0]["sha256"], again.attachments[0]["sha256"])


if __name__ == "__main__":
    unittest.main()
