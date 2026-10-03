import unittest

from phishkit.models import Severity
from phishkit.parser import parse_email
from phishkit.urls import analyze_urls, defang, extract_urls
from tests.helpers import make_eml


def run(text="", html=None, headers=None):
    return analyze_urls(parse_email(make_eml(text=text, html=html, headers=headers)))


def flags_for(urls, needle):
    return next(u for u in urls if needle in u["url"])["flags"]


def finding(findings, title):
    return next((f for f in findings if f.title == title), None)


class DefangTests(unittest.TestCase):
    def test_defang(self):
        self.assertEqual(defang("https://evil.com/x.php?a=b.c"), "hxxps://evil[.]com/x.php?a=b.c")
        self.assertEqual(defang("http://1.2.3.4/"), "hxxp://1[.]2[.]3[.]4/")


class ExtractTests(unittest.TestCase):
    def test_text_urls_strip_trailing_punctuation(self):
        urls = extract_urls("See https://example.com/a). Also (www.example.org/b), done.", "")
        self.assertEqual([u["url"] for u in urls], ["https://example.com/a", "www.example.org/b"])

    def test_duplicates_merged_with_sources(self):
        html = '<a href="https://example.com/a">click</a>'
        urls = extract_urls("https://example.com/a", html)
        self.assertEqual(len(urls), 1)
        self.assertEqual(sorted(urls[0]["sources"]), ["html:a", "text"])
        self.assertEqual(urls[0]["anchor_texts"], ["click"])

    def test_html_sources(self):
        html = ('<form action="https://collect.evil.test/post"><input name=p></form>'
                '<meta http-equiv="refresh" content="0; url=https://redirect.evil.test/">'
                '<a href="mailto:x@y.com">mail</a><a href="#top">top</a>')
        urls = {u["url"]: u for u in extract_urls("", html)}
        self.assertIn("https://collect.evil.test/post", urls)
        self.assertIn("html:form", urls["https://collect.evil.test/post"]["sources"])
        self.assertIn("https://redirect.evil.test/", urls)
        self.assertEqual(len(urls), 2)


class HeuristicTests(unittest.TestCase):
    def test_clean_link_has_no_flags(self):
        urls, findings = run(html='<a href="https://example.com/news">Read more</a>')
        self.assertEqual(urls[0]["flags"], [])
        self.assertEqual(findings, [])

    def test_link_text_mismatch(self):
        urls, findings = run(html='<a href="https://evil.test/login">https://www.paypal.com/signin</a>')
        self.assertIn("text_mismatch", urls[0]["flags"])
        self.assertEqual(finding(findings, "Link text shows a different domain").severity, Severity.HIGH)

    def test_anchor_text_that_is_not_a_domain_is_ignored(self):
        urls, _ = run(html='<a href="https://example.com/d">Hi Mr.Smith, open report.pdf</a>')
        self.assertNotIn("text_mismatch", urls[0]["flags"])

    def test_bare_domain_anchor_text_mismatch(self):
        urls, _ = run(html='<a href="https://evil.test/x">Visit microsoft.com</a>')
        self.assertIn("text_mismatch", urls[0]["flags"])

    def test_ip_host(self):
        urls, findings = run("Go to http://192.0.2.44/office365/login.php now")
        self.assertIn("ip_host", urls[0]["flags"])
        self.assertEqual(finding(findings, "Link points to a raw IP address").severity, Severity.HIGH)

    def test_shortener(self):
        urls, findings = run("https://bit.ly/3xYz")
        self.assertIn("shortener", urls[0]["flags"])
        self.assertEqual(finding(findings, "URL shortener hides the destination").severity, Severity.MEDIUM)

    def test_punycode(self):
        urls, findings = run("https://xn--ypal-43d9g.com/login")
        self.assertIn("punycode", urls[0]["flags"])
        self.assertIsNotNone(finding(findings, "Punycode (internationalised) domain in link"))

    def test_brand_in_subdomain(self):
        urls, findings = run("https://paypal.com.verify-acct.xyz/login")
        self.assertIn("brand_in_subdomain", urls[0]["flags"])
        self.assertEqual(finding(findings, "Brand name used in an unrelated domain").severity, Severity.HIGH)

    def test_userinfo_trick(self):
        urls, _ = run("https://www.microsoft.com@evil.test/login")
        self.assertIn("userinfo", urls[0]["flags"])
        self.assertEqual(urls[0]["domain"], "evil.test")

    def test_javascript_scheme(self):
        urls, findings = run(html='<a href="javascript:alert(document.cookie)">x</a>')
        self.assertIn("dangerous_scheme", urls[0]["flags"])
        self.assertEqual(finding(findings, "Link uses a script or data URI").severity, Severity.HIGH)

    def test_form_posting_off_domain(self):
        _, findings = run(html='<form action="https://collect.evil.test/p"><input type=password></form>')
        self.assertEqual(finding(findings, "HTML form in email body").severity, Severity.HIGH)

    def test_insecure_http_is_low(self):
        _, findings = run("http://example.com/page")
        self.assertEqual(finding(findings, "Unencrypted (http) link").severity, Severity.LOW)

    def test_one_finding_per_flag_type(self):
        _, findings = run("http://192.0.2.1/a http://192.0.2.2/b http://192.0.2.3/c")
        ip_findings = [f for f in findings if f.title == "Link points to a raw IP address"]
        self.assertEqual(len(ip_findings), 1)
        self.assertIn("3 links", ip_findings[0].detail)


if __name__ == "__main__":
    unittest.main()
