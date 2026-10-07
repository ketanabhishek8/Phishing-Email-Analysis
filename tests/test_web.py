import io
import json
import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.helpers import make_eml
from web.app import create_app
from web.store import Store

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.store = Store(str(Path(self.dir) / "t.db"))

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_save_get_list_stats(self):
        report = {"summary": {"subject": "Hi", "from": "a@b.c"}, "score": 60, "verdict": "Likely phishing"}
        rid = self.store.save("x.eml", report)
        row = self.store.get(rid)
        self.assertEqual(row["report"]["score"], 60)
        self.assertEqual(row["filename"], "x.eml")
        self.assertEqual(self.store.list()[0]["subject"], "Hi")
        self.assertEqual(self.store.stats()["Likely phishing"], 1)
        self.assertEqual(self.store.stats()["total"], 1)
        self.assertIsNone(self.store.get(999))


class WebTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.app = create_app(db_path=str(Path(self.dir) / "t.db"), testing=True)
        self.client = self.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.dir)

    def csrf(self):
        html = self.client.get("/").get_data(as_text=True)
        return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)

    def upload(self, data: bytes, filename="mail.eml", token=None, **extra):
        form = {"file": (io.BytesIO(data), filename), "csrf_token": token or self.csrf()}
        form.update(extra)
        return self.client.post("/analyze", data=form, content_type="multipart/form-data")

    def test_index_has_csrf_token_and_security_headers(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn('name="csrf_token"', resp.get_data(as_text=True))
        csp = resp.headers["Content-Security-Policy"]
        self.assertIn("default-src 'self'", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertEqual(resp.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(resp.headers["X-Frame-Options"], "DENY")

    def test_upload_redirects_to_report(self):
        resp = self.upload((SAMPLES / "02-paypal-spoof-punycode.eml").read_bytes())
        self.assertEqual(resp.status_code, 302)
        self.assertRegex(resp.headers["Location"], r"/report/\d+$")
        page = self.client.get(resp.headers["Location"]).get_data(as_text=True)
        self.assertIn("Likely phishing", page)
        self.assertIn("hxxp://198[.]51[.]100[.]23/paypal/webscr", page)

    def test_email_urls_are_never_clickable(self):
        resp = self.upload((SAMPLES / "02-paypal-spoof-punycode.eml").read_bytes())
        page = self.client.get(resp.headers["Location"]).get_data(as_text=True)
        self.assertNotIn('href="http://198.51.100.23', page)
        self.assertNotIn('href="https://xn--', page)
        self.assertNotIn("bit.ly", re.sub(r"hxxps?://bit\[\.\]ly", "", page).replace("bit[.]ly", ""))

    def test_hostile_content_is_escaped(self):
        raw = make_eml(headers={"Subject": "<script>alert(1)</script>"},
                       html='<img src=x onerror="alert(2)"><script>alert(3)</script>',
                       attachments=[('<b onmouseover="x">.html', b"<script>alert(4)</script>", "text", "html")])
        resp = self.upload(raw)
        page = self.client.get(resp.headers["Location"]).get_data(as_text=True)
        self.assertNotIn("<script>alert", page)
        self.assertNotIn('<img src=x', page)
        self.assertNotIn('<b onmouseover', page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)

    def test_missing_csrf_rejected(self):
        resp = self.client.post("/analyze", data={"file": (io.BytesIO(make_eml()), "m.eml")},
                                content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 400)

    def test_non_eml_rejected(self):
        resp = self.upload(b"MZ...", filename="evil.exe")
        self.assertEqual(resp.status_code, 400)
        self.assertIn(".eml", resp.get_data(as_text=True))

    def test_empty_file_rejected(self):
        resp = self.upload(b"", filename="empty.eml")
        self.assertEqual(resp.status_code, 400)

    def test_oversize_upload_is_413(self):
        resp = self.upload(b"x" * (10 * 1024 * 1024 + 10))
        self.assertEqual(resp.status_code, 413)

    def test_api_analyze_returns_json_without_saving(self):
        resp = self.client.post("/api/analyze", data={"file": (io.BytesIO(make_eml()), "m.eml")},
                                content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["verdict"], "Clean")
        self.assertEqual(self.client.get("/dashboard").get_data(as_text=True).count('class="row-link"'), 0)

    def test_api_analyze_requires_file(self):
        resp = self.client.post("/api/analyze", data={}, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("error", resp.get_json())

    def test_api_report_json(self):
        loc = self.upload(make_eml()).headers["Location"]
        rid = loc.rsplit("/", 1)[1]
        data = self.client.get(f"/api/report/{rid}").get_json()
        self.assertEqual(data["verdict"], "Clean")
        self.assertEqual(self.client.get("/api/report/999").status_code, 404)

    def test_dashboard_lists_analyses_and_counts(self):
        self.upload((SAMPLES / "06-legit-newsletter.eml").read_bytes(), filename="06.eml")
        self.upload((SAMPLES / "04-bec-ceo-fraud.eml").read_bytes(), filename="04.eml")
        page = self.client.get("/dashboard").get_data(as_text=True)
        self.assertEqual(page.count('class="row-link"'), 2)
        self.assertIn("Urgent - confidential request", page)
        self.assertIn('data-count-clean="1"', page)
        self.assertIn('data-count-phishing="1"', page)

    def test_empty_dashboard_invites_upload(self):
        page = self.client.get("/dashboard").get_data(as_text=True)
        self.assertIn("No emails analysed yet", page)

    def test_sample_route_analyses_bundled_sample(self):
        resp = self.client.post("/samples/05-html-smuggling.eml", data={"csrf_token": self.csrf()})
        self.assertEqual(resp.status_code, 302)
        page = self.client.get(resp.headers["Location"]).get_data(as_text=True)
        self.assertIn("HTML smuggling attachment", page)

    def test_sample_route_rejects_unknown_names(self):
        resp = self.client.post("/samples/..%2F..%2Fetc%2Fpasswd", data={"csrf_token": self.csrf()})
        self.assertEqual(resp.status_code, 404)

    def test_unknown_report_404(self):
        self.assertEqual(self.client.get("/report/12345").status_code, 404)


class ReportLayoutTests(unittest.TestCase):
    """The report leads with the verdict, what to do next and the main reasons."""

    MOODS = ("idle", "eager", "inspecting", "happy", "worried", "alarmed", "shrug")

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.client = create_app(db_path=str(Path(self.dir) / "t.db"), testing=True).test_client()

    def tearDown(self):
        shutil.rmtree(self.dir)

    def report_for(self, sample):
        token = re.search(r'name="csrf_token" value="([^"]+)"', self.client.get("/").get_data(as_text=True)).group(1)
        resp = self.client.post(f"/samples/{sample}", data={"csrf_token": token})
        return self.client.get(resp.headers["Location"]).get_data(as_text=True)

    @staticmethod
    def reasons(page):
        block = re.search(r'<ul class="reason-list">(.*?)</ul>', page, re.S)
        return re.findall(r'<span class="reason-title">([^<]+)</span>', block.group(1)) if block else []

    def test_phishing_report_says_what_to_do_and_why(self):
        page = self.report_for("02-paypal-spoof-punycode.eml")
        self.assertIn("What to do now", page)
        self.assertIn("Report it.", page)
        self.assertIn("Main reasons", page)
        reasons = self.reasons(page)
        self.assertEqual(len(reasons), 3)
        self.assertIn("SPF failed", reasons)
        self.assertIn("Link text shows a different domain", reasons)  # ties spread across categories
        self.assertIn('class="postie postie--alarmed"', page)

    def test_main_reasons_are_the_heaviest_findings(self):
        data = self.client.post("/api/analyze", content_type="multipart/form-data", data={
            "file": (io.BytesIO((SAMPLES / "03-invoice-macro-attachment.eml").read_bytes()), "m.eml")}).get_json()
        weights = {f["title"]: f["weight"] for f in data["findings"]}
        page = self.report_for("03-invoice-macro-attachment.eml")
        shown = self.reasons(page)
        self.assertTrue(shown)
        lightest_shown = min(weights[t] for t in shown)
        hidden = [w for t, w in weights.items() if t not in shown]
        self.assertTrue(all(w <= lightest_shown for w in hidden), (shown, weights))

    def test_clean_report_reassures_without_alarm(self):
        page = self.report_for("06-legit-newsletter.eml")
        self.assertIn("Nothing here looks like phishing.", page)
        self.assertNotIn("Report it.", page)
        self.assertIn('class="postie postie--happy"', page)
        self.assertIn("What Postie checked", page)

    def test_report_renders_only_its_own_mood(self):
        page = self.report_for("02-paypal-spoof-punycode.eml")
        verdict = page[page.index('<section class="verdict'):page.index('<div class="meter">')]
        self.assertIn("m-alarmed", verdict)
        for mood in self.MOODS:
            if mood != "alarmed":
                self.assertNotIn(f"m-{mood}", verdict)

    def test_upload_page_postie_can_switch_every_mood(self):
        page = self.client.get("/").get_data(as_text=True)
        self.assertIn("data-postie-live", page)
        for mood in self.MOODS:
            self.assertIn(f"m-{mood}", page)

    def test_upload_page_hides_server_configuration_details(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("VT_API_KEY", None)
            page = self.client.get("/").get_data(as_text=True)
        self.assertNotIn("VT_API_KEY", page)
        self.assertIn("Not set up on this server.", page)

    def test_error_page_has_a_shrugging_postie(self):
        page = self.client.get("/report/12345").get_data(as_text=True)
        self.assertIn('class="postie postie--shrug"', page)


if __name__ == "__main__":
    unittest.main()
