"""Regression tests for hostile-input hardening and correctness fixes."""

import io
import json
import os
import re
import shutil
import tempfile
import time
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import dkim

from phishkit import analyzer, dmarc, domains, spf
from phishkit.analyzer import analyze
from phishkit.auth import analyze_auth, verify_dkim
from phishkit.cli import main as cli_main
from phishkit.models import Severity
from phishkit.parser import parse_email
from phishkit.render import render_text
from phishkit.urls import analyze_urls, extract_urls
from tests.fakedns import FakeResolver
from tests.helpers import make_eml

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).parent / "fixtures"
PRIVATE_KEY = (FIXTURES / "dkim_test_key.pem").read_bytes()
DKIM_RECORD = "v=DKIM1; k=rsa; p=" + (FIXTURES / "dkim_test_key.pub").read_text().strip()


def titles(findings):
    return [f.title for f in findings]


def zip_bytes(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return bytearray(buf.getvalue())


def with_attachment(name, payload):
    return make_eml(attachments=[(name, bytes(payload), "application", "octet-stream")])


class HostileInputNeverCrashes(unittest.TestCase):
    def test_zip_with_invalid_utf8_name(self):
        data = zip_bytes({"ab.txt": "x"})
        central = data.find(b"PK\x01\x02")
        data[central + 9] |= 0x08  # high byte of the general-purpose flags: bit 11 = UTF-8 names
        name_at = central + 46
        data[name_at:name_at + 2] = b"\xff\xfe"
        report = analyze(with_attachment("a.zip", data))
        self.assertEqual(len(report.attachments), 1)

    def test_zip_with_unsupported_version(self):
        data = zip_bytes({"[Content_Types].xml": "x", "word/document.xml": "x"})
        central = data.find(b"PK\x01\x02")
        data[central + 6] = 0xFF  # version needed to extract
        report = analyze(with_attachment("a.docx", data))
        self.assertEqual(len(report.attachments), 1)

    def test_charset_with_nul(self):
        raw = b'From: a@example.com\r\nSubject: s\r\nContent-Type: text/plain; charset="x\x00"\r\n\r\nbody\xe9\r\n'
        self.assertIn("body", analyze(raw).body_preview["text"])

    def test_unexpected_module_error_becomes_finding(self):
        with mock.patch.object(analyzer, "analyze_urls", side_effect=RuntimeError("boom")):
            report = analyze(make_eml())
        self.assertIn("Part of the analysis failed", titles(report.findings))


class LiveDkimNeverCrashes(unittest.TestCase):
    def signed(self):
        raw = make_eml()
        return dkim.sign(raw, b"s1", b"example.com", PRIVATE_KEY,
                         include_headers=[b"from", b"subject"]) + raw

    def resolver(self, record=DKIM_RECORD):
        return FakeResolver({("TXT", "s1._domainkey.example.com"): [record]})

    def test_empty_length_tag(self):
        raw = self.signed().replace(b"DKIM-Signature: v=1;", b"DKIM-Signature: v=1; l=;", 1)
        self.assertEqual(verify_dkim(raw, self.resolver())[0]["result"], "permerror")

    def test_bad_base64_body_hash(self):
        raw = re.sub(rb"bh=[^;]+;", b"bh=rsa-sha1;", self.signed(), count=1)
        self.assertIn(verify_dkim(raw, self.resolver())[0]["result"], ("permerror", "fail"))

    def test_garbage_key_record(self):
        result = verify_dkim(self.signed(), self.resolver("\xff"))[0]["result"]
        self.assertIn(result, ("permerror", "key unavailable"))


class LinearTime(unittest.TestCase):
    LIMIT = 2.0

    def timed(self, raw):
        start = time.perf_counter()
        analyze(raw)
        return time.perf_counter() - start

    def test_many_form_tags_in_html_attachment(self):
        raw = make_eml(attachments=[("x.html", b"<form" * 20000, "text", "html")])
        self.assertLess(self.timed(raw), self.LIMIT)

    def test_url_followed_by_many_parentheses(self):
        self.assertLess(self.timed(make_eml(text="http://x" + ")" * 100000)), self.LIMIT)

    def test_huge_from_header(self):
        self.assertLess(self.timed(make_eml(headers={"From": "a" * 40000})), self.LIMIT)


class TerminalOutputIsInert(unittest.TestCase):
    def test_escape_sequences_are_neutralised(self):
        raw = make_eml(headers={"Subject": "Invoice\x1b[2A\x1b[2KVerdict: Clean"},
                       attachments=[("a\x1b[31m.pdf", b"%PDF-1.4", "application", "pdf")])
        out = render_text(analyze(raw), color=False)
        self.assertNotIn("\x1b", out)
        self.assertIn("\\x1b", out)

    def test_bidi_controls_are_made_visible(self):
        raw = make_eml(attachments=[("invoice‮fdp.exe", b"MZ" + b"\0" * 64, "application", "octet-stream")])
        out = render_text(analyze(raw), color=False)
        self.assertNotIn("‮", out)
        self.assertIn("<U+202E>", out)


class SpfUnsupportedInsideInclude(unittest.TestCase):
    def test_include_using_exists_is_neutral_not_fail(self):
        r = FakeResolver({
            ("TXT", "example.com"): ["v=spf1 include:_spf.sf.example -all"],
            ("TXT", "_spf.sf.example"): ["v=spf1 exists:%{i}._spf.sf.example -all"],
        })
        self.assertEqual(spf.check_spf("192.0.2.1", "example.com", r)[0], "neutral")

    def test_macro_only_in_exp_is_ignored(self):
        r = FakeResolver({("TXT", "example.com"): ["v=spf1 ip4:198.51.100.7 -all exp=explain.%{d}"]})
        self.assertEqual(spf.check_spf("198.51.100.7", "example.com", r)[0], "pass")


class BrowserStyleUrls(unittest.TestCase):
    def flags(self, href):
        urls, _ = analyze_urls(parse_email(make_eml(html=f'<a href="{href}">x</a>')))
        return urls[0]["flags"]

    def test_protocol_relative(self):
        self.assertIn("ip_host", self.flags("//198.51.100.9/paypal/login"))

    def test_backslashes(self):
        self.assertIn("ip_host", self.flags("https:\\\\198.51.100.9\\login"))

    def test_single_slash(self):
        self.assertIn("ip_host", self.flags("https:/198.51.100.9/login"))

    def test_whitespace_inside_scheme(self):
        self.assertIn("dangerous_scheme", self.flags("java\tscript:alert(1)"))

    def test_relative_links_are_not_flagged(self):
        urls, findings = analyze_urls(parse_email(make_eml(html='<img src="header.png"><a href="/account">x</a>')))
        self.assertTrue(all(u["flags"] == [] for u in urls))
        self.assertEqual(findings, [])

    def test_newsletter_images_get_host_checks_only(self):
        html = ('<img src="http://cdn.example.net/icons/facebook.png">'
                '<img src="https://cdn.example.net/social/linkedin-circle.png">')
        _, findings = analyze_urls(parse_email(make_eml(html=html)))
        self.assertEqual(findings, [])

    def test_image_on_raw_ip_still_flagged(self):
        urls, _ = analyze_urls(parse_email(make_eml(html='<img src="http://198.51.100.9/t.gif">')))
        self.assertIn("ip_host", urls[0]["flags"])

    def test_img_src_extracted(self):
        urls = extract_urls("", '<img src="https://track.example/t.gif" width=1 height=1>')
        self.assertEqual(urls[0]["sources"], ["html:img"])


class UntrustedAuthHeaders(unittest.TestCase):
    def test_arc_alone_is_not_trusted(self):
        raw = make_eml(extra=[("ARC-Authentication-Results",
                               "i=1; mx.google.com; spf=pass smtp.mailfrom=paypal.com; dkim=pass header.d=paypal.com; dmarc=pass header.from=paypal.com")])
        section, findings = analyze_auth(parse_email(raw))
        self.assertEqual(section["recorded"]["dmarc"]["result"], "none")
        self.assertIn("No authentication results recorded", titles(findings))
        self.assertTrue(section["other_headers"])

    def test_received_spf_alone_is_not_trusted(self):
        raw = make_eml(extra=[("Received-SPF", "pass (forged) client-ip=192.0.2.1;")])
        section, findings = analyze_auth(parse_email(raw))
        self.assertEqual(section["recorded"]["spf"]["result"], "none")
        self.assertIn("No authentication results recorded", titles(findings))

    def test_header_without_spf_dkim_dmarc_wording(self):
        raw = make_eml(extra=[("Authentication-Results", "mx.example.org; auth=pass smtp.auth=x")])
        _, findings = analyze_auth(parse_email(raw))
        f = next(f for f in findings if f.title == "No authentication results recorded")
        self.assertNotIn("has no Authentication-Results", f.detail)

    def test_bestguesspass_means_no_dmarc_record(self):
        raw = make_eml(extra=[("Authentication-Results", "spf=pass smtp.mailfrom=a.test; dkim=pass header.d=a.test; dmarc=bestguesspass action=none header.from=a.test")])
        _, findings = analyze_auth(parse_email(raw))
        f = next(f for f in findings if f.title == "No DMARC policy")
        self.assertEqual(f.severity, Severity.LOW)


class DmarcTags(unittest.TestCase):
    def test_uppercase_strict_mode(self):
        policy = dmarc.parse_record("v=DMARC1; p=REJECT; adkim=S; aspf=S")
        self.assertEqual((policy["p"], policy["adkim"], policy["aspf"]), ("reject", "s", "s"))

    def test_subdomain_policy_applies_when_inherited(self):
        r = FakeResolver({("TXT", "_dmarc.example.com"): ["v=DMARC1; p=reject; sp=none"]})
        policy = dmarc.fetch_policy("news.example.com", r)
        self.assertEqual(policy["effective"], "none")
        self.assertEqual(dmarc.fetch_policy("example.com", r)["effective"], "reject")


class LookalikePrecision(unittest.TestCase):
    def test_brand_owned_domains(self):
        for d in ("www.google-analytics.com", "s.amazon-adsystem.com", "apple-dns.net", "linkedin-ei.com"):
            self.assertIsNone(domains.lookalike_of(d), d)

    def test_generic_words_containing_short_brands(self):
        for d in ("meta-analysis.org", "chase-hotels.com"):
            self.assertIsNone(domains.lookalike_of(d), d)

    def test_short_brand_with_bait_word(self):
        self.assertEqual(domains.lookalike_of("dhl-parcel-tracking.com"), "dhl.com")

    def test_brand_tokens_are_normalised_too(self):
        self.assertEqual(domains.lookalike_of("icloud-verify.com"), "apple.com")


class HiddenDirectionCharacters(unittest.TestCase):
    def test_bidi_in_subject_is_flagged(self):
        report = analyze(make_eml(headers={"Subject": "Payment ‮detaler"}))
        self.assertIn("Hidden text-direction characters in headers", titles(report.findings))


class CliRobustness(unittest.TestCase):
    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli_main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_batch_continues_past_unreadable_file(self):
        fd, path = tempfile.mkstemp(suffix=".eml")
        with os.fdopen(fd, "wb") as fh:
            fh.write(make_eml())
        try:
            code, out, err = self.run_cli("analyze", path, "/no/such.eml", "--json")
        finally:
            os.remove(path)
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(out)[0]["verdict"], "Clean")
        self.assertIn("cannot read", err)


class SampleHygiene(unittest.TestCase):
    def test_free_mail_addresses_in_samples_are_clearly_fictional(self):
        pattern = re.compile(rb"([\w.+-]+)@(gmail\.com|outlook\.com|hotmail\.com|yahoo\.com)", re.I)
        for path in (ROOT / "samples").glob("*.eml"):
            for local, _ in pattern.findall(path.read_bytes()):
                self.assertTrue(local.lower().startswith(b"phishkit-sample"), (path.name, local))


class WebHardening(unittest.TestCase):
    def setUp(self):
        from web.app import create_app
        self.dir = tempfile.mkdtemp()
        self.app = create_app(db_path=str(Path(self.dir) / "t.db"), testing=True)
        self.client = self.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_cross_origin_api_post_rejected(self):
        resp = self.client.post("/api/analyze?live=1&vt=1", headers={"Origin": "https://evil.example"},
                                data={"file": (io.BytesIO(make_eml()), "m.eml")}, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 403)

    def test_same_origin_api_post_allowed(self):
        resp = self.client.post("/api/analyze", headers={"Origin": "http://localhost"},
                                data={"file": (io.BytesIO(make_eml()), "m.eml")}, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 200)

    def test_foreign_host_header_rejected(self):
        self.assertEqual(self.client.get("/", headers={"Host": "attacker.example"}).status_code, 400)

    def test_uploads_are_buffered_in_memory(self):
        with self.app.test_request_context("/"):
            from flask import request
            stream = request._get_file_stream(5_000_000, "message/rfc822", "big.eml")
        self.assertIsInstance(stream, io.BytesIO)

    def test_rtlo_filename_rendered_visibly(self):
        html = self.client.get("/").get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
        raw = make_eml(attachments=[("inv‮fdp.exe", b"MZ" + b"\0" * 64, "application", "octet-stream")])
        resp = self.client.post("/analyze", data={"file": (io.BytesIO(raw), "m.eml"), "csrf_token": token},
                                content_type="multipart/form-data")
        page = self.client.get(resp.headers["Location"]).get_data(as_text=True)
        self.assertNotIn("‮", page)
        self.assertIn("&lt;U+202E&gt;", page)


if __name__ == "__main__":
    unittest.main()
