"""The VirusTotal box, per-item results and links on the report page, and VT lines in the CLI."""

import json
import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from phishkit.analyzer import analyze
from phishkit.intel import VTClient, url_id
from phishkit.render import render_text
from tests.test_intel import FakeOpener, stats_body
from web.app import create_app

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
PAYPAL = (SAMPLES / "02-paypal-spoof-punycode.eml").read_bytes()
INVOICE = (SAMPLES / "03-invoice-macro-attachment.eml").read_bytes()


def urls_of(raw):
    return [u["url"] for u in analyze(raw).urls]


class VTReportPageTests(unittest.TestCase):
    HOST = "phishkit-demo.vercel.app"

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.client = create_app(db_path=str(Path(self.tmp) / "never.db"), testing=True, hosted=True).test_client()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def page_for(self, report_dict):
        """Render a report the way the hosted app re-renders a saved history entry."""
        base = f"https://{self.HOST}"
        html = self.client.get("/", base_url=base).get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
        entry = {"filename": "m.eml", "created_at": "2026-10-14T10:00:00+00:00", "report": report_dict}
        resp = self.client.post("/history/view", base_url=base, data={"csrf_token": token, "entry": json.dumps(entry)})
        self.assertEqual(resp.status_code, 200)
        return resp.get_data(as_text=True)

    @staticmethod
    def box(page):
        match = re.search(r'<section class="card vt-card".*?</section>', page, re.S)
        return match.group(0) if match else ""

    def paypal_with_vt(self):
        urls = urls_of(PAYPAL)
        ip_link = next(u for u in urls if "198.51.100.23" in u)
        shortener = next(u for u in urls if "bit.ly" in u)
        routes = {url_id(ip_link): (200, stats_body(malicious=3)), url_id(shortener): (200, stats_body())}
        client = VTClient("k", opener=FakeOpener(routes))
        return analyze(PAYPAL, vt=True, vt_client=client).to_dict(), ip_link, shortener

    def test_box_summarises_what_was_checked(self):
        report, _, _ = self.paypal_with_vt()
        box = self.box(self.page_for(report))
        self.assertIn("Checked 4 links", box)
        self.assertIn("1 flagged", box)
        self.assertIn("1 known and not flagged", box)
        self.assertIn("2 not seen before", box)
        self.assertIn("never sent", box)

    def test_flagged_and_known_items_link_to_virustotal(self):
        report, ip_link, shortener = self.paypal_with_vt()
        page = self.page_for(report)
        for link in (ip_link, shortener):
            href = f'href="https://www.virustotal.com/gui/url/{url_id(link)}"'
            self.assertIn(href, page)
        self.assertIn('rel="noopener noreferrer"', page)
        self.assertIn("VirusTotal: not seen before", page)

    def test_attachment_links_to_its_file_page(self):
        sha = analyze(INVOICE).attachments[0]["sha256"]
        client = VTClient("k", opener=FakeOpener({sha: (200, stats_body(malicious=40))}))
        page = self.page_for(analyze(INVOICE, vt=True, vt_client=client).to_dict())
        self.assertIn(f'href="https://www.virustotal.com/gui/file/{sha}"', page)
        self.assertIn("Checked 1 attachment", self.box(page))

    def test_tampered_saved_links_are_not_rendered(self):
        report, _, _ = self.paypal_with_vt()
        bad = ["javascript:alert(1)", "https://evil.example/gui/url/abc",
               "https://www.virustotal.com/gui/url/abc\" onmouseover=\"x", "https://www.virustotal.com.evil.example/gui/url/a"]
        checked = [u for u in report["urls"] if u.get("vt", {}).get("status") == "found"]
        for u, link in zip(checked * 2, bad):
            u["vt"]["link"] = link
            page = self.page_for(report)
            self.assertNotIn(link, page)
            self.assertNotIn("javascript:", page)

    def test_no_box_when_virustotal_was_not_requested(self):
        page = self.page_for(analyze(PAYPAL).to_dict())
        self.assertEqual(self.box(page), "")
        self.assertNotIn("virustotal.com", page)

    def test_box_explains_an_early_stop(self):
        urls = urls_of(PAYPAL)
        routes = {url_id(urls[0]): (429, b"{}")}
        client = VTClient("k", opener=FakeOpener(routes))
        report = analyze(PAYPAL, vt=True, vt_client=client).to_dict()
        box = self.box(self.page_for(report))
        self.assertIn("rate limit", box)
        self.assertIn("not checked", box)

    def test_box_says_when_no_key_is_set(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("VT_API_KEY", None)
            report = analyze(PAYPAL, vt=True).to_dict()
        self.assertIn("not set up", self.box(self.page_for(report)))

    def test_box_with_nothing_to_check(self):
        raw = b"From: a@example.com\r\nTo: b@example.com\r\nSubject: hi\r\n\r\nplain text, no links\r\n"
        client = VTClient("k", opener=FakeOpener({}))
        box = self.box(self.page_for(analyze(raw, vt=True, vt_client=client).to_dict()))
        self.assertIn("no links or attachments to look up", box)


class VTTextOutputTests(unittest.TestCase):
    def test_cli_text_shows_url_results(self):
        url = next(u for u in urls_of(PAYPAL) if "198.51.100.23" in u)
        client = VTClient("k", opener=FakeOpener({url_id(url): (200, stats_body(malicious=3, suspicious=1))}))
        text = render_text(analyze(PAYPAL, vt=True, vt_client=client), color=False)
        self.assertIn("VirusTotal: 3 malicious / 1 suspicious", text)
        self.assertIn("VirusTotal: not seen before", text)


if __name__ == "__main__":
    unittest.main()
