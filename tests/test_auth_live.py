import unittest
from pathlib import Path

import dkim

from phishkit import dmarc, spf
from phishkit.auth import analyze_auth, originating_ip, verify_dkim
from phishkit.models import Severity
from phishkit.parser import parse_email
from tests.fakedns import FakeResolver
from tests.helpers import make_eml

FIXTURES = Path(__file__).parent / "fixtures"
PRIVATE_KEY = (FIXTURES / "dkim_test_key.pem").read_bytes()
PUBLIC_KEY = (FIXTURES / "dkim_test_key.pub").read_text().strip()
DKIM_RECORD = f"v=DKIM1; k=rsa; p={PUBLIC_KEY}"


def signed_email(body="Hello Bob", domain="example.com", selector="s1"):
    raw = make_eml(text=body)
    sig = dkim.sign(raw, selector.encode(), domain.encode(), PRIVATE_KEY,
                    include_headers=[b"from", b"to", b"subject", b"date", b"message-id"])
    return sig + raw


class SpfTests(unittest.TestCase):
    def test_ip4_cidr_pass(self):
        r = FakeResolver({("TXT", "example.com"): ["v=spf1 ip4:198.51.100.0/24 -all"]})
        self.assertEqual(spf.check_spf("198.51.100.7", "example.com", r)[0], "pass")

    def test_ip6_pass(self):
        r = FakeResolver({("TXT", "example.com"): ["v=spf1 ip6:2001:db8::/32 -all"]})
        self.assertEqual(spf.check_spf("2001:db8::1", "example.com", r)[0], "pass")

    def test_include_chain_pass(self):
        r = FakeResolver({
            ("TXT", "example.com"): ["v=spf1 include:_spf.mailer.test ~all"],
            ("TXT", "_spf.mailer.test"): ["v=spf1 ip4:203.0.113.0/24 -all"],
        })
        self.assertEqual(spf.check_spf("203.0.113.9", "example.com", r)[0], "pass")

    def test_hard_fail(self):
        r = FakeResolver({("TXT", "example.com"): ["v=spf1 ip4:198.51.100.0/24 -all"]})
        self.assertEqual(spf.check_spf("192.0.2.1", "example.com", r)[0], "fail")

    def test_softfail(self):
        r = FakeResolver({("TXT", "example.com"): ["v=spf1 ip4:198.51.100.0/24 ~all"]})
        self.assertEqual(spf.check_spf("192.0.2.1", "example.com", r)[0], "softfail")

    def test_a_and_mx_mechanisms(self):
        r = FakeResolver({
            ("TXT", "example.com"): ["v=spf1 a mx -all"],
            ("A", "example.com"): ["192.0.2.10"],
            ("MX", "example.com"): ["mx1.example.com"],
            ("A", "mx1.example.com"): ["192.0.2.20"],
        })
        self.assertEqual(spf.check_spf("192.0.2.10", "example.com", r)[0], "pass")
        self.assertEqual(spf.check_spf("192.0.2.20", "example.com", r)[0], "pass")

    def test_redirect(self):
        r = FakeResolver({
            ("TXT", "example.com"): ["v=spf1 redirect=_spf.example.net"],
            ("TXT", "_spf.example.net"): ["v=spf1 ip4:192.0.2.0/24 -all"],
        })
        self.assertEqual(spf.check_spf("192.0.2.5", "example.com", r)[0], "pass")

    def test_include_loop_is_permerror(self):
        r = FakeResolver({
            ("TXT", "a.test"): ["v=spf1 include:b.test -all"],
            ("TXT", "b.test"): ["v=spf1 include:a.test -all"],
        })
        self.assertEqual(spf.check_spf("192.0.2.1", "a.test", r)[0], "permerror")

    def test_no_record_is_none(self):
        r = FakeResolver({("TXT", "example.com"): ["google-site-verification=abc"]})
        self.assertEqual(spf.check_spf("192.0.2.1", "example.com", r)[0], "none")

    def test_dns_timeout_is_temperror(self):
        r = FakeResolver({("TXT", "example.com"): "timeout"})
        self.assertEqual(spf.check_spf("192.0.2.1", "example.com", r)[0], "temperror")

    def test_unsupported_mechanism_is_neutral(self):
        r = FakeResolver({("TXT", "example.com"): ["v=spf1 exists:%{i}.spf.example.com -all"]})
        result, detail = spf.check_spf("192.0.2.1", "example.com", r)
        self.assertEqual(result, "neutral")
        self.assertIn("not supported", detail)


class DmarcTests(unittest.TestCase):
    def test_fetch_policy(self):
        r = FakeResolver({("TXT", "_dmarc.example.com"): ["v=DMARC1; p=reject; adkim=s; rua=mailto:d@example.com"]})
        policy = dmarc.fetch_policy("example.com", r)
        self.assertEqual(policy["p"], "reject")
        self.assertEqual(policy["adkim"], "s")
        self.assertEqual(policy["aspf"], "r")

    def test_falls_back_to_org_domain(self):
        r = FakeResolver({("TXT", "_dmarc.example.com"): ["v=DMARC1; p=quarantine"]})
        policy = dmarc.fetch_policy("mail.example.com", r)
        self.assertEqual(policy["p"], "quarantine")
        self.assertEqual(policy["domain"], "example.com")

    def test_no_policy(self):
        self.assertIsNone(dmarc.fetch_policy("example.com", FakeResolver()))

    def test_relaxed_alignment_allows_subdomain(self):
        a = dmarc.alignment("example.com", "bounce.example.com", ["mail.example.com"], "r", "r")
        self.assertTrue(a["spf_aligned"])
        self.assertTrue(a["dkim_aligned"])

    def test_strict_alignment_needs_exact_match(self):
        a = dmarc.alignment("example.com", "bounce.example.com", ["mail.example.com"], "s", "s")
        self.assertFalse(a["spf_aligned"])
        self.assertFalse(a["dkim_aligned"])

    def test_unrelated_domains_not_aligned(self):
        a = dmarc.alignment("paypal.com", "evil.test", ["evil.test"], "r", "r")
        self.assertFalse(a["spf_aligned"] or a["dkim_aligned"])


class DkimTests(unittest.TestCase):
    def test_valid_signature_passes(self):
        r = FakeResolver({("TXT", "s1._domainkey.example.com"): [DKIM_RECORD]})
        results = verify_dkim(signed_email(), r)
        self.assertEqual(results[0]["result"], "pass")
        self.assertEqual(results[0]["domain"], "example.com")
        self.assertEqual(results[0]["selector"], "s1")

    def test_tampered_body_fails(self):
        raw = signed_email().replace(b"Hello Bob", b"Pay me now")
        r = FakeResolver({("TXT", "s1._domainkey.example.com"): [DKIM_RECORD]})
        self.assertEqual(verify_dkim(raw, r)[0]["result"], "fail")

    def test_missing_key_is_key_unavailable(self):
        result = verify_dkim(signed_email(), FakeResolver())[0]
        self.assertEqual(result["result"], "key unavailable")

    def test_unsigned_email(self):
        self.assertEqual(verify_dkim(make_eml(), FakeResolver()), [])


class OriginatingIpTests(unittest.TestCase):
    def test_prefers_received_spf_client_ip(self):
        e = parse_email(make_eml(extra=[("Received-SPF", "pass (x) client-ip=198.51.100.7;")]))
        self.assertEqual(originating_ip(e), "198.51.100.7")

    def test_skips_private_hops(self):
        e = parse_email(make_eml(extra=[
            ("Received", "from internal (internal [10.0.0.5]) by mx2.example.org; Fri, 02 Oct 2026 10:00:06 +0000"),
            ("Received", "from sender.example.com (sender.example.com [198.51.100.7]) by mx.example.org; Fri, 02 Oct 2026 10:00:05 +0000"),
        ]))
        self.assertEqual(originating_ip(e), "198.51.100.7")


class LiveAnalyzeTests(unittest.TestCase):
    def setUp(self):
        self.extra = [("Received", "from sender.example.com (sender.example.com [198.51.100.7]) by mx.example.org; Fri, 02 Oct 2026 10:00:05 +0000")]

    def test_live_spoof_of_reject_domain(self):
        raw = make_eml(headers={"From": "PayPal <service@paypal.com>", "Return-Path": "<x@evil.test>"}, extra=self.extra)
        r = FakeResolver({
            ("TXT", "evil.test"): ["v=spf1 ip4:198.51.100.0/24 -all"],
            ("TXT", "_dmarc.paypal.com"): ["v=DMARC1; p=reject"],
        })
        section, findings = analyze_auth(parse_email(raw), live=True, resolver=r)
        live = section["live"]
        self.assertEqual(live["spf"]["result"], "pass")
        self.assertEqual(live["dmarc"]["result"], "fail")
        self.assertEqual(live["dmarc"]["policy"]["p"], "reject")
        self.assertFalse(live["alignment"]["spf_aligned"])
        dmarc_fail = next(f for f in findings if f.title == "DMARC failed (live check)")
        self.assertEqual(dmarc_fail.severity, Severity.HIGH)

    def test_live_does_not_double_count_recorded_results(self):
        raw = make_eml(
            headers={"From": "PayPal <service@paypal.com>", "Return-Path": "<x@evil.test>"},
            extra=[("Authentication-Results", "mx.example.org; spf=pass smtp.mailfrom=evil.test; dmarc=fail header.from=paypal.com")] + self.extra,
        )
        r = FakeResolver({
            ("TXT", "evil.test"): ["v=spf1 ip4:198.51.100.0/24 -all"],
            ("TXT", "_dmarc.paypal.com"): ["v=DMARC1; p=reject"],
        })
        _, findings = analyze_auth(parse_email(raw), live=True, resolver=r)
        dmarc_findings = [f for f in findings if f.title.startswith("DMARC failed")]
        self.assertEqual(len(dmarc_findings), 1)

    def test_dns_timeouts_do_not_crash(self):
        raw = make_eml(headers={"Return-Path": "<a@example.com>"}, extra=self.extra)
        r = FakeResolver({("TXT", "example.com"): "timeout", ("TXT", "_dmarc.example.com"): "timeout"})
        section, _ = analyze_auth(parse_email(raw), live=True, resolver=r)
        self.assertEqual(section["live"]["spf"]["result"], "temperror")
        self.assertEqual(section["live"]["dmarc"]["result"], "temperror")

    def test_p_none_flagged(self):
        raw = make_eml(headers={"Return-Path": "<a@example.com>"}, extra=self.extra)
        r = FakeResolver({
            ("TXT", "example.com"): ["v=spf1 ip4:198.51.100.7 -all"],
            ("TXT", "_dmarc.example.com"): ["v=DMARC1; p=none"],
        })
        _, findings = analyze_auth(parse_email(raw), live=True, resolver=r)
        self.assertIn("DMARC policy is monitor-only (p=none)", [f.title for f in findings])


if __name__ == "__main__":
    unittest.main()
