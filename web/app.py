"""Flask app: upload an .eml, view the report, browse past analyses.

Security posture (the app handles hostile input by design):
- email HTML is never rendered, only shown as escaped source; Jinja autoescaping is on
- URLs from emails are defanged and never emitted as links
- strict Content-Security-Policy, no inline scripts or external assets
- CSRF token on every form post; the JSON API is stateless (never writes to the database)
- uploads capped at 10 MB and kept in memory only
"""

from __future__ import annotations

import hmac
import os
import re
import secrets
from pathlib import Path

from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for

from phishkit import __version__
from phishkit.analyzer import analyze
from phishkit.models import Severity
from phishkit.urls import defang

from .store import Store

ROOT = Path(__file__).resolve().parent.parent
SAMPLES_DIR = ROOT / "samples"
MAX_UPLOAD = 10 * 1024 * 1024

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")

SEVERITY_ORDER = [s.label for s in sorted(Severity, reverse=True)]

SAMPLE_TITLES = {
    "01-m365-credential-harvest.eml": "Microsoft 365 password-expiry lure",
    "02-paypal-spoof-punycode.eml": "PayPal spoof with punycode links",
    "03-invoice-macro-attachment.eml": "Overdue invoice with a macro document",
    "04-bec-ceo-fraud.eml": "CEO wire-transfer request (BEC)",
    "05-html-smuggling.eml": "DocuSign lure with HTML smuggling",
    "06-legit-newsletter.eml": "Legitimate newsletter",
}


def _sample_names() -> list[str]:
    if not SAMPLES_DIR.is_dir():
        return []
    return sorted(p.name for p in SAMPLES_DIR.glob("*.eml"))


def create_app(db_path: str | None = None, testing: bool = False) -> Flask:
    app = Flask(__name__, instance_path=str(ROOT / "instance"))
    app.config.update(
        SECRET_KEY=os.environ.get("PHISHKIT_SECRET_KEY") or secrets.token_hex(32),
        MAX_CONTENT_LENGTH=MAX_UPLOAD,
        TESTING=testing,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
    )
    store = Store(db_path or str(Path(app.instance_path) / "phishkit.db"))
    app.extensions["phishkit_store"] = store

    # ------------------------------------------------------------- helpers

    def csrf_token() -> str:
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return session["csrf"]

    def check_csrf():
        sent = request.form.get("csrf_token", "")
        expected = session.get("csrf", "")
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400, description="Your session expired or the form was submitted from another site. "
                                   "Reload the page and try again.")

    def read_upload() -> tuple[str, bytes]:
        upload = request.files.get("file")
        if upload is None or not upload.filename:
            abort(400, description="Choose an .eml file to analyse.")
        filename = os.path.basename(upload.filename)
        if not filename.lower().endswith(".eml"):
            abort(400, description="Only .eml files can be analysed. In Outlook or Gmail, use "
                                   "'Save as' or 'Download message' to get the .eml file.")
        data = upload.read()
        if not data.strip():
            abort(400, description="That file is empty. Choose a saved email (.eml) with content.")
        return filename, data

    def run_and_save(filename: str, data: bytes):
        report = analyze(data, live=bool(request.form.get("live")), vt=bool(request.form.get("vt")))
        rid = store.save(filename, report.to_dict())
        return redirect(url_for("report", analysis_id=rid))

    @app.context_processor
    def inject():
        return {"csrf_token": csrf_token, "version": __version__, "severity_order": SEVERITY_ORDER,
                "vt_configured": bool(os.environ.get("VT_API_KEY"))}

    @app.template_filter("verdict_class")
    def verdict_class(verdict: str) -> str:
        return {"Clean": "clean", "Suspicious": "suspicious", "Likely phishing": "phishing"}.get(verdict, "")

    url_pattern = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+")

    @app.template_filter("defang_text")
    def defang_text(text: str) -> str:
        """Defang every URL inside free text (body previews, link text). Output is still autoescaped."""
        return url_pattern.sub(lambda m: defang(m.group(0)), text or "")

    @app.template_filter("filesize")
    def filesize(n: int) -> str:
        for unit in ("bytes", "KB", "MB"):
            if n < 1024 or unit == "MB":
                return f"{n:.0f} {unit}" if unit == "bytes" else f"{n:.1f} {unit}"
            n /= 1024
        return str(n)

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    # -------------------------------------------------------------- routes

    @app.get("/")
    def index():
        samples = [(n, SAMPLE_TITLES.get(n, n.removesuffix(".eml"))) for n in _sample_names()]
        return render_template("index.html", samples=samples, recent=store.list(limit=5))

    @app.post("/analyze")
    def analyze_upload():
        check_csrf()
        filename, data = read_upload()
        return run_and_save(filename, data)

    @app.post("/samples/<name>")
    def analyze_sample(name: str):
        check_csrf()
        if name not in _sample_names():
            abort(404)
        return run_and_save(name, (SAMPLES_DIR / name).read_bytes())

    @app.get("/report/<int:analysis_id>")
    def report(analysis_id: int):
        row = store.get(analysis_id)
        if row is None:
            abort(404)
        return render_template("report.html", row=row, r=row["report"])

    @app.get("/dashboard")
    def dashboard():
        return render_template("dashboard.html", rows=store.list(), stats=store.stats())

    @app.post("/api/analyze")
    def api_analyze():
        upload = request.files.get("file")
        if upload is None:
            return jsonify(error="send the email as multipart form field 'file'"), 400
        data = upload.read()
        if not data.strip():
            return jsonify(error="the uploaded file is empty"), 400
        live = request.args.get("live") in ("1", "true")
        vt = request.args.get("vt") in ("1", "true")
        return jsonify(analyze(data, live=live, vt=vt).to_dict())

    @app.get("/api/report/<int:analysis_id>")
    def api_report(analysis_id: int):
        row = store.get(analysis_id)
        if row is None:
            return jsonify(error="no such report"), 404
        return jsonify(row["report"])

    # -------------------------------------------------------------- errors

    @app.errorhandler(400)
    @app.errorhandler(404)
    @app.errorhandler(413)
    def error(exc):
        messages = {
            404: "There is nothing at this address. It may have been a report from another database.",
            413: "That file is larger than 10 MB. Emails over this size are usually large attachments; "
                 "analyse a copy without them or use the command line tool.",
        }
        message = messages.get(exc.code) or exc.description
        if request.path.startswith("/api/"):
            return jsonify(error=message), exc.code
        return render_template("error.html", code=exc.code, message=message), exc.code

    return app
