"""Hosted (serverless) mode: stateless, works on any domain, no shared secrets needed."""

import importlib
import io
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from flask import Flask

from tests.helpers import make_eml
from web.app import create_app

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"


class EntrypointTests(unittest.TestCase):
    def test_root_app_module_exposes_flask_app(self):
        module = importlib.import_module("app")
        self.assertIsInstance(module.app, Flask)

    def test_static_assets_live_in_public(self):
        for name in ("style.css", "app.js", "favicon.svg"):
            self.assertTrue((ROOT / "public" / "static" / name).is_file(), name)

    def test_local_mode_still_serves_static(self):
        tmp = tempfile.mkdtemp()
        try:
            client = create_app(db_path=str(Path(tmp) / "t.db"), testing=True, hosted=False).test_client()
            self.assertEqual(client.get("/static/style.css").status_code, 200)
        finally:
            shutil.rmtree(tmp)


class HostedModeTests(unittest.TestCase):
    HOST = "phishkit-demo.vercel.app"

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = Path(self.tmp) / "never.db"
        self.app = create_app(db_path=str(self.db), testing=True, hosted=True)
        self.client = self.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def get(self, path, **kw):
        return self.client.get(path, base_url=f"https://{self.HOST}", **kw)

    def post(self, path, **kw):
        return self.client.post(path, base_url=f"https://{self.HOST}", **kw)

    def token(self):
        html = self.get("/").get_data(as_text=True)
        return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)

    def test_any_public_host_is_served(self):
        self.assertEqual(self.get("/").status_code, 200)

    def test_upload_renders_report_directly_and_stores_nothing(self):
        resp = self.post("/analyze", data={"file": (io.BytesIO((SAMPLES / "04-bec-ceo-fraud.eml").read_bytes()), "m.eml"),
                                           "csrf_token": self.token()}, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 200)
        page = resp.get_data(as_text=True)
        self.assertIn("Likely phishing", page)
        self.assertIn("not stored", page)
        self.assertFalse(self.db.exists())

    def test_sample_button_works(self):
        resp = self.post("/samples/06-legit-newsletter.eml", data={"csrf_token": self.token()})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Clean", resp.get_data(as_text=True))

    def test_csrf_survives_a_different_instance(self):
        # Serverless: the form may be served by one instance and posted to another.
        token = self.token()
        other = create_app(db_path=str(self.db), testing=True, hosted=True)
        client2 = other.test_client()
        for cookie in self.client._cookies.values():
            client2.set_cookie(cookie.key, cookie.value, domain=self.HOST)
        resp = client2.post("/samples/06-legit-newsletter.eml", base_url=f"https://{self.HOST}",
                            data={"csrf_token": token})
        self.assertEqual(resp.status_code, 200)

    def test_missing_csrf_still_rejected(self):
        self.get("/")
        self.assertEqual(self.post("/samples/06-legit-newsletter.eml", data={}).status_code, 400)

    def test_cross_origin_post_rejected(self):
        resp = self.post("/api/analyze?vt=1", headers={"Origin": "https://evil.example"},
                         data={"file": (io.BytesIO(make_eml()), "m.eml")}, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 403)

    def test_same_origin_post_allowed_on_public_domain(self):
        resp = self.post("/api/analyze", headers={"Origin": f"https://{self.HOST}"},
                         data={"file": (io.BytesIO(make_eml()), "m.eml")}, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 200)

    def test_proxy_rewritten_host_does_not_break_same_origin_clicks(self):
        # Behind Vercel's proxy the Host the app sees can differ from the browser's address.
        token = self.token()
        internal = "phishing-email-analysis-2pokt-tsurai.vercel.app"
        # The browser sends the cookie for its own address; the test client keys cookies by the
        # host it requests, so mirror the cookie onto the internal host the app sees.
        self.client.set_cookie("phishkit_csrf", token, domain=internal)
        resp = self.client.post("/samples/06-legit-newsletter.eml",
                                base_url=f"https://{internal}",
                                headers={"Origin": f"https://{self.HOST}", "Sec-Fetch-Site": "same-origin"},
                                data={"csrf_token": token})
        self.assertEqual(resp.status_code, 200)

    def test_browser_reported_cross_site_post_rejected(self):
        resp = self.post("/api/analyze", headers={"Sec-Fetch-Site": "cross-site"},
                         data={"file": (io.BytesIO(make_eml()), "m.eml")}, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 403)

    def test_rejections_are_logged_for_diagnosis(self):
        with self.assertLogs("phishkit.web", level="WARNING") as logs:
            self.post("/api/analyze", headers={"Origin": "https://evil.example"},
                      data={"file": (io.BytesIO(make_eml()), "m.eml")}, content_type="multipart/form-data")
        self.assertIn("evil.example", "\n".join(logs.output))

    def test_unexpected_error_gets_a_helpful_page(self):
        from unittest import mock
        with mock.patch("web.app.analyze", side_effect=RuntimeError("boom")):
            resp = self.post("/samples/06-legit-newsletter.eml", data={"csrf_token": self.token()})
        self.assertEqual(resp.status_code, 500)
        self.assertIn("Something went wrong", resp.get_data(as_text=True))

    def test_server_side_history_routes_disabled(self):
        self.assertEqual(self.get("/report/1").status_code, 404)
        self.assertEqual(self.get("/api/report/1").status_code, 404)

    # ---- browser-side history (localStorage) ----

    def report_page(self, raw=None, name="m.eml"):
        raw = raw or (SAMPLES / "04-bec-ceo-fraud.eml").read_bytes()
        return self.post("/analyze", data={"file": (io.BytesIO(raw), name), "csrf_token": self.token()},
                         content_type="multipart/form-data").get_data(as_text=True)

    def embedded(self, page):
        import json
        block = re.search(r'<script type="application/json" id="phishkit-report">(.*?)</script>', page, re.S)
        self.assertIsNotNone(block, "report page must embed its data for browser history")
        return json.loads(block.group(1))

    def test_report_page_embeds_data_for_browser_history(self):
        data = self.embedded(self.report_page())
        self.assertEqual(data["filename"], "m.eml")
        self.assertEqual(data["report"]["verdict"], "Likely phishing")
        self.assertIn("created_at", data)

    def test_embedded_data_cannot_break_out_of_script_block(self):
        raw = make_eml(headers={"Subject": "</script><script>alert(1)</script>"})
        page = self.report_page(raw)
        self.assertNotIn("<script>alert(1)", page)
        self.assertEqual(self.embedded(page)["report"]["summary"]["subject"], "</script><script>alert(1)</script>")

    def test_dashboard_is_built_from_browser_history(self):
        page = self.get("/dashboard").get_data(as_text=True)
        self.assertIn("data-browser-history", page)
        self.assertIn("<noscript>", page)
        self.assertIn("saved in this browser", page)

    def test_view_saved_report_rerenders_it(self):
        import json
        saved = self.embedded(self.report_page())
        resp = self.post("/history/view", data={"csrf_token": self.token(), "entry": json.dumps(saved)})
        self.assertEqual(resp.status_code, 200)
        page = resp.get_data(as_text=True)
        self.assertIn("Urgent - confidential request", page)
        self.assertNotIn('id="phishkit-report"', page)  # viewing must not save a duplicate

    def test_view_rejects_malformed_entries(self):
        for entry in ("not json", "[]", '{"report": {"verdict": 5}}', '{"filename": "x"}'):
            resp = self.post("/history/view", data={"csrf_token": self.token(), "entry": entry})
            self.assertEqual(resp.status_code, 400, entry)

    def test_view_requires_csrf(self):
        self.get("/")
        self.assertEqual(self.post("/history/view", data={"entry": "{}"}).status_code, 400)

    def test_view_escapes_hostile_saved_data(self):
        import json
        saved = self.embedded(self.report_page())
        saved["report"]["summary"]["subject"] = "<img src=x onerror=alert(1)>"
        page = self.post("/history/view", data={"csrf_token": self.token(),
                                                "entry": json.dumps(saved)}).get_data(as_text=True)
        self.assertNotIn("<img src=x", page)
        self.assertIn("&lt;img src=x", page)

    def test_footer_does_not_claim_local_processing(self):
        page = self.get("/").get_data(as_text=True)
        self.assertNotIn("Runs on this computer", page)
        self.assertIn("hosted", page.lower())

    def test_upload_limit_fits_serverless_body_limit(self):
        resp = self.post("/analyze", data={"file": (io.BytesIO(b"x" * (4 * 1024 * 1024 + 10)), "m.eml"),
                                           "csrf_token": self.token()}, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 413)


class HostedDetectionTests(unittest.TestCase):
    def test_vercel_env_enables_hosted_mode(self):
        import os
        from unittest import mock
        with mock.patch.dict(os.environ, {"VERCEL": "1"}):
            app = create_app(testing=True)
        self.assertTrue(app.config["PHISHKIT_HOSTED"])


if __name__ == "__main__":
    unittest.main()
