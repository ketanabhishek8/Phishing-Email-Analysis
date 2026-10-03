import unittest

from phishkit.models import Severity
from phishkit.parser import parse_email
from phishkit.senders import analyze_senders
from tests.helpers import make_eml


def run(headers):
    return analyze_senders(parse_email(make_eml(headers=headers)))


def finding(findings, title):
    return next((f for f in findings if f.title == title), None)


class SenderTests(unittest.TestCase):
    def test_consistent_sender_has_no_findings(self):
        section, findings = run({"Reply-To": "alice@example.com", "Return-Path": "<bounce@mail.example.com>"})
        self.assertEqual(section["from_domain"], "example.com")
        self.assertEqual(section["from_name"], "Alice")
        self.assertEqual(findings, [])

    def test_reply_to_other_domain_is_high(self):
        section, findings = run({"Reply-To": "ceo.office@gmail.com"})
        f = finding(findings, "Reply-To differs from From")
        self.assertEqual(f.severity, Severity.HIGH)
        self.assertIn("reply_to", section["mismatches"])

    def test_return_path_other_domain_is_low(self):
        _, findings = run({"Return-Path": "<bounce@sendgrid.net>"})
        self.assertEqual(finding(findings, "Return-Path differs from From").severity, Severity.LOW)

    def test_message_id_domain_mismatch(self):
        _, findings = run({"Message-ID": "<123@mailer.evil.test>"})
        self.assertIsNotNone(finding(findings, "Message-ID domain differs from From"))

    def test_brand_display_name_from_unrelated_domain_is_high(self):
        _, findings = run({"From": "PayPal Service <service@evil.ru>"})
        f = finding(findings, "Display name impersonates a brand")
        self.assertEqual(f.severity, Severity.HIGH)
        self.assertIn("paypal", f.detail.lower())

    def test_brand_display_name_from_real_domain_is_fine(self):
        _, findings = run({"From": "PayPal <service@paypal.com>", "Message-ID": "<1@paypal.com>"})
        self.assertIsNone(finding(findings, "Display name impersonates a brand"))

    def test_email_address_in_display_name_is_high(self):
        _, findings = run({"From": '"ceo@company.com" <attacker@gmail.com>'})
        f = finding(findings, "Display name contains a different email address")
        self.assertEqual(f.severity, Severity.HIGH)

    def test_lookalike_from_domain_is_critical(self):
        section, findings = run({"From": "Microsoft 365 <no-reply@rnicrosoft-online.com>"})
        f = finding(findings, "Lookalike sender domain")
        self.assertEqual(f.severity, Severity.CRITICAL)
        self.assertEqual(section["lookalike"], "microsoft.com")

    def test_freemail_posing_as_organisation_is_medium(self):
        _, findings = run({"From": "IT Helpdesk <it.helpdesk.desk@gmail.com>"})
        f = finding(findings, "Free webmail account posing as an organisation")
        self.assertEqual(f.severity, Severity.MEDIUM)

    def test_missing_from(self):
        _, findings = run({"From": None})
        self.assertIsNotNone(finding(findings, "Missing From address"))


if __name__ == "__main__":
    unittest.main()
