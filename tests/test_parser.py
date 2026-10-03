import unittest

from phishkit.parser import parse_email
from tests.helpers import make_eml


class ParserTests(unittest.TestCase):
    def test_basic_headers_and_bodies(self):
        raw = make_eml(html="<p>Hi <a href='https://example.com'>here</a></p>")
        e = parse_email(raw)
        self.assertEqual(e.subject, "Hello")
        self.assertEqual(e.from_, "Alice <alice@example.com>")
        self.assertEqual(e.message_id, "<abc123@example.com>")
        self.assertIn("Hello Bob", e.text_body)
        self.assertIn("href='https://example.com'", e.html_body)
        self.assertEqual(e.raw, raw)

    def test_attachment_extracted(self):
        raw = make_eml(attachments=[("report.pdf", b"%PDF-1.7 data", "application", "pdf")])
        e = parse_email(raw)
        self.assertEqual(len(e.attachments), 1)
        a = e.attachments[0]
        self.assertEqual(a.filename, "report.pdf")
        self.assertEqual(a.content_type, "application/pdf")
        self.assertEqual(a.payload, b"%PDF-1.7 data")

    def test_received_hops_newest_first_with_ips(self):
        raw = make_eml(extra=[
            ("Received", "from mx.example.org (mx.example.org [203.0.113.5]) by inbox.example.org with ESMTPS; Fri, 02 Oct 2026 10:00:05 +0000"),
            ("Received", "from sender.example.com (sender.example.com [IPv6:2001:db8::1]) by mx.example.org with ESMTP; Fri, 02 Oct 2026 10:00:02 +0000"),
        ])
        e = parse_email(raw)
        self.assertEqual(len(e.received), 2)
        self.assertEqual(e.received[0].ip, "203.0.113.5")
        self.assertEqual(e.received[0].by_host, "inbox.example.org")
        self.assertEqual(e.received[1].ip, "2001:db8::1")
        self.assertEqual(e.received[1].from_host, "sender.example.com")

    def test_get_all_keeps_duplicates_in_order(self):
        raw = make_eml(extra=[("X-Test", "one"), ("X-Test", "two")])
        e = parse_email(raw)
        self.assertEqual(e.get_all("x-test"), ["one", "two"])
        self.assertEqual(e.get("X-TEST"), "one")
        self.assertIsNone(e.get("X-Missing"))

    def test_rfc2231_filename_decoded(self):
        raw = (
            b"From: a@example.com\r\nTo: b@example.org\r\nSubject: s\r\n"
            b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=XX\r\n\r\n"
            b"--XX\r\nContent-Type: text/plain\r\n\r\nbody\r\n"
            b"--XX\r\nContent-Type: application/octet-stream\r\n"
            b"Content-Disposition: attachment; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf\r\n"
            b"Content-Transfer-Encoding: base64\r\n\r\nJVBERi0=\r\n--XX--\r\n"
        )
        e = parse_email(raw)
        self.assertEqual(e.attachments[0].filename, "résumé.pdf")
        self.assertEqual(e.attachments[0].payload, b"%PDF-")

    def test_bogus_charset_does_not_raise(self):
        raw = (
            b"From: a@example.com\r\nSubject: s\r\nContent-Type: text/plain; charset=bogus-8\r\n\r\n"
            b"caf\xe9 body\r\n"
        )
        e = parse_email(raw)
        self.assertIn("body", e.text_body)

    def test_garbage_input_returns_best_effort(self):
        e = parse_email(b"\x00\x01\x02 not an email at all \xff\xfe")
        self.assertEqual(e.subject, "")
        self.assertEqual(e.attachments, [])

    def test_empty_input(self):
        e = parse_email(b"")
        self.assertIn("empty", " ".join(e.parse_errors).lower())


if __name__ == "__main__":
    unittest.main()
