import unittest

from phishkit.auth import analyze_auth, parse_auth_results
from phishkit.models import Severity
from phishkit.parser import parse_email
from tests.helpers import make_eml

GOOGLE_AR = (
    "mx.google.com;\r\n       dkim=pass header.i=@example.com header.s=s1 header.b=AbC123;\r\n"
    "       spf=pass (google.com: domain of bounce@example.com designates 198.51.100.7 as permitted sender) "
    "smtp.mailfrom=bounce@example.com;\r\n"
    "       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com"
)


def auth_for(extra):
    return analyze_auth(parse_email(make_eml(extra=extra)))


def titles(findings):
    return [f.title for f in findings]


class ParseAuthResultsTests(unittest.TestCase):
    def test_parses_methods_props_and_comments(self):
        parsed = parse_auth_results(" ".join(GOOGLE_AR.split()))
        self.assertEqual(parsed["authserv_id"], "mx.google.com")
        methods = {r["method"]: r for r in parsed["results"]}
        self.assertEqual(methods["spf"]["result"], "pass")
        self.assertEqual(methods["spf"]["props"]["smtp.mailfrom"], "bounce@example.com")
        self.assertEqual(methods["dkim"]["props"]["header.i"], "@example.com")
        self.assertEqual(methods["dmarc"]["props"]["header.from"], "example.com")
        self.assertIn("p=REJECT", methods["dmarc"]["comment"])

    def test_microsoft_style_header_without_authserv_id(self):
        parsed = parse_auth_results(
            "spf=none (sender IP is 192.0.2.1) smtp.mailfrom=evil.test; dkim=fail (body hash did not verify) "
            "header.d=microsoft.com;dmarc=fail action=oreject header.from=microsoft.com;compauth=fail reason=000")
        self.assertEqual(parsed["authserv_id"], "")
        methods = {r["method"]: r["result"] for r in parsed["results"]}
        self.assertEqual(methods, {"spf": "none", "dkim": "fail", "dmarc": "fail", "compauth": "fail"})

    def test_none_result(self):
        parsed = parse_auth_results("mx.example.org; none")
        self.assertEqual(parsed["results"], [])

    def test_semicolon_inside_comment_does_not_split(self):
        parsed = parse_auth_results("mx.example.org; spf=fail (sender; not permitted) smtp.mailfrom=a@b.com")
        self.assertEqual(len(parsed["results"]), 1)
        self.assertEqual(parsed["results"][0]["props"]["smtp.mailfrom"], "a@b.com")


class RecordedAuthTests(unittest.TestCase):
    def test_all_pass_with_folded_header(self):
        raw = b"Authentication-Results: " + GOOGLE_AR.encode() + b"\r\n" + make_eml()
        section, findings = analyze_auth(parse_email(raw))
        rec = section["recorded"]
        self.assertEqual(rec["spf"]["result"], "pass")
        self.assertEqual(rec["dkim"]["result"], "pass")
        self.assertEqual(rec["dmarc"]["result"], "pass")
        self.assertEqual(section["authserv_id"], "mx.google.com")
        self.assertEqual(section["dkim_domains"], ["example.com"])
        self.assertFalse([f for f in findings if f.severity > Severity.INFO])

    def test_missing_header_means_none_not_fail(self):
        section, findings = auth_for([])
        for method in ("spf", "dkim", "dmarc"):
            self.assertEqual(section["recorded"][method]["result"], "none")
            self.assertIn("not recorded", section["recorded"][method]["detail"])
        self.assertIn("No authentication results recorded", titles(findings))
        self.assertTrue(all(f.severity == Severity.INFO for f in findings))

    def test_only_topmost_header_trusted(self):
        section, findings = auth_for([
            ("Authentication-Results", "mx.example.org; spf=fail smtp.mailfrom=x@evil.test; dmarc=fail header.from=paypal.com"),
            ("Authentication-Results", "forged.evil.test; spf=pass; dkim=pass; dmarc=pass"),
        ])
        self.assertEqual(section["recorded"]["spf"]["result"], "fail")
        self.assertEqual(len(section["other_headers"]), 1)

    def test_unsigned_dkim_detail_is_readable(self):
        section, _ = auth_for([("Authentication-Results", "mx.example.org; dkim=none (message not signed)")])
        self.assertNotIn("?", section["recorded"]["dkim"]["detail"])
        self.assertIn("message not signed", section["recorded"]["dkim"]["detail"])

    def test_header_d_none_is_not_a_domain(self):
        section, _ = auth_for([("Authentication-Results", "spf=none smtp.mailfrom=a.test; dkim=none (message not signed) header.d=none; dmarc=none header.from=a.test")])
        self.assertEqual(section["dkim_domains"], [])
        self.assertNotIn("none=none", section["recorded"]["dkim"]["detail"])

    def test_dmarc_fail_is_high(self):
        _, findings = auth_for([("Authentication-Results", "mx.example.org; dmarc=fail (p=REJECT) header.from=paypal.com")])
        f = next(f for f in findings if f.title == "DMARC failed")
        self.assertEqual(f.severity, Severity.HIGH)

    def test_spf_softfail_is_medium(self):
        _, findings = auth_for([("Authentication-Results", "mx.example.org; spf=softfail smtp.mailfrom=a@b.com")])
        f = next(f for f in findings if f.title == "SPF softfail")
        self.assertEqual(f.severity, Severity.MEDIUM)

    def test_received_spf_used_when_ar_lacks_spf(self):
        section, findings = auth_for([
            ("Authentication-Results", "mx.example.org; dkim=none"),
            ("Received-SPF", "fail (mx.example.org: domain of a@evil.test does not designate 192.0.2.9 as permitted sender) client-ip=192.0.2.9;"),
        ])
        self.assertEqual(section["recorded"]["spf"]["result"], "fail")
        self.assertEqual(section["recorded"]["spf"]["source"], "Received-SPF")
        self.assertIn("SPF failed", titles(findings))

    def test_arc_alone_is_listed_but_not_trusted(self):
        # The sender can write ARC headers; without a receiver-stamped result they are claims only.
        section, _ = auth_for([
            ("ARC-Authentication-Results", "i=1; mx.microsoft.com 1; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com"),
        ])
        self.assertEqual(section["recorded"]["dmarc"]["result"], "none")
        self.assertTrue(section["other_headers"][0].startswith("ARC-Authentication-Results"))


if __name__ == "__main__":
    unittest.main()
