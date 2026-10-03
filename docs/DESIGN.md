# PhishKit — Phishing Email Analysis Toolkit (Design)

Date: 2026-10-03 · Status: approved

## 1. Goal

A Python tool that takes an `.eml` file and reports SPF/DKIM/DMARC results, sender
mismatches, suspicious URLs and attachment hashes, usable both as a CLI and as a
local web app with a dashboard. It is a portfolio/coursework submission, so the
code must be clean, tested and documented, and the demo must include analysis of
sample phishing emails plus a write-up on organisational phishing defences.

### Success criteria

- `python -m phishkit analyze <file.eml>` prints a readable report; `--json` emits
  machine-readable output with the same content.
- The web app (Flask, `127.0.0.1` only) accepts an upload, shows a report page,
  keeps a dashboard of past analyses, and exposes `POST /api/analyze`.
- Every sample email in `samples/` produces the expected verdict in tests.
- Test suite runs offline with stdlib `unittest`.
- README, sample-analysis write-up and defences write-up exist and are accurate.

### Non-goals

- Public internet deployment, user accounts, multi-tenant storage.
- Rendering email HTML, detonating attachments, or sandboxing.
- Full Public Suffix List support (a small built-in list is used; documented).

## 2. Constraints

- Python 3.13, dependencies isolated in `./.venv`: Flask, dkimpy, dnspython.
- No other installs without asking. Tests use stdlib `unittest`.
- Network access only when explicitly requested: `--live` (DNS) and `--vt`
  (VirusTotal, requires `VT_API_KEY`). Default analysis is fully offline.
- Public-corpus samples are downloaded only after a separate confirmation listing
  exact files, source and size. LetsDefend samples need the user's login, so the
  user exports those manually.

## 3. Architecture

```
phishkit/
  __init__.py
  __main__.py        # enables `python -m phishkit`
  models.py          # dataclasses: Finding, Severity, AuthResult, UrlInfo, AttachmentInfo, Report
  parser.py          # .eml bytes -> ParsedEmail (headers, received chain, bodies, attachments, raw)
  auth.py            # recorded + live SPF/DKIM/DMARC
  dnsutil.py         # thin resolver wrapper (TXT/A/AAAA/MX) — the single seam faked in tests
  domains.py         # org-domain, punycode/homoglyph/lookalike helpers, brand list
  senders.py         # From/Reply-To/Return-Path/Sender/Message-ID consistency, display-name spoofing
  urls.py            # URL extraction from text + HTML, heuristics, defanging
  attachments.py     # hashes, magic-byte type check, risky ext, macros, encrypted zip, HTML smuggling
  intel.py           # optional VirusTotal v3 lookups (stdlib urllib)
  scoring.py         # findings -> 0-100 score + verdict
  analyzer.py        # orchestrates the above: analyze(raw_bytes, live=False, vt=False) -> Report
  render.py          # Report -> ANSI terminal text
  cli.py             # argparse entrypoint
web/
  app.py             # Flask factory: create_app(db_path)
  store.py           # SQLite persistence of reports (JSON blob + summary columns)
  templates/         # base, index (upload), report, dashboard
  static/            # style.css (no external CDNs)
samples/             # crafted .eml files (+ corpus/ if downloaded)
tests/               # unittest suites per module + web tests
docs/                # sample-analyses.md, defending-against-phishing.md
```

Data flow: `raw bytes → parser → {auth, senders, urls, attachments, intel} →
list[Finding] + section data → scoring → Report → render (CLI) | JSON | Jinja (web)`.

Each analysis module exposes one function taking `ParsedEmail` (plus options) and
returning its section data and a list of `Finding`s. Modules do not import each
other except shared helpers (`domains`, `dnsutil`, `models`).

## 4. Components

### 4.1 models
- `Severity`: info, low, medium, high, critical (with numeric weight).
- `Finding(category, severity, title, detail, evidence)`.
- `Report`: summary (subject, from, to, date, message-id), auth, senders, urls,
  attachments, received hops, findings, score, verdict, `to_dict()`.

### 4.2 parser
- Uses `email.message_from_bytes(raw, policy=email.policy.default)`.
- Extracts: all headers (ordered, duplicates kept), Received chain parsed into
  hops (from/by/ip/timestamp), text and HTML bodies (decoded, charset-safe),
  attachments (filename, declared content-type, payload bytes), including
  inline parts with filenames. Malformed input yields best-effort data plus a
  parse finding rather than an exception.

### 4.3 auth
- **Recorded:** parse `Authentication-Results`, `ARC-Authentication-Results`,
  `Received-SPF` into per-mechanism results (spf/dkim/dmarc → pass/fail/
  softfail/neutral/none/temperror/permerror) with properties (smtp.mailfrom,
  header.d, header.from). Only the topmost (most recent) Authentication-Results
  is trusted; others are listed as informational, since attackers can forge
  lower ones.
- **Live (`live=True`):**
  - DKIM: `dkim.verify(raw, dnsfunc=...)` per signature; key-not-found is
    reported as "key unavailable", not fail.
  - SPF: determine originating IP (first external hop in Received chain), fetch
    SPF for the Return-Path domain and evaluate `ip4`, `ip6`, `a`, `mx`,
    `include`, `redirect`, `all` with qualifiers; 10-lookup limit → permerror.
  - DMARC: fetch `_dmarc.<from-domain>` (falling back to org domain), parse
    `p`, `sp`, `adkim`, `aspf`, `pct`; compute alignment of SPF domain and DKIM
    `d=` against the From domain (relaxed = org-domain match, strict = exact).
- Findings: auth failures, missing DMARC record, `p=none` policy, misalignment.

### 4.4 senders
- Compare From domain vs Reply-To, Return-Path, Sender, Message-ID domain.
- Display-name spoofing: display name contains an email address with a
  different domain, or a known brand name not matching the From domain.
- Lookalike detection via `domains.py`: punycode/IDN, digit/letter swaps
  (`0/o`, `1/l`, `rn/m`), edit distance ≤ 2 to a brand domain, brand embedded
  in a longer domain (`paypal-secure-login.com`).
- Free-mail sender claiming to be an organisation.

### 4.5 urls
- Extract from plain text (regex) and HTML (`html.parser`: `a[href]`,
  `form[action]`, `img[src]`, `area[href]`, meta refresh). Keep anchor text.
- Heuristics: IP-literal host, punycode, shortener domain, suspicious TLD,
  `@` userinfo trick, excessive subdomains, brand in subdomain/path but not
  registered domain, visible-text URL ≠ href domain, http (non-TLS) links,
  `data:`/`javascript:` schemes, very long URL, form posting off-domain.
- Output: deduplicated list with defanged URL, domain, sources, flags.

### 4.6 attachments
- MD5, SHA1, SHA256, size.
- Magic-byte detection (PE/MZ, ELF, ZIP/OOXML, OLE2, PDF, RAR, 7z, gzip, ISO,
  LNK, HTML, script heuristics) vs extension and declared content type.
- Flags: risky extensions (exe, scr, js, vbs, hta, iso, img, lnk, docm, xlsm,
  one, …), double extensions (`invoice.pdf.exe`), OOXML with
  `vbaProject.bin`, OLE2 with macros marker, encrypted zip entries, HTML
  attachments containing scripts/forms (smuggling), right-to-left override
  in filename.
- Attachment bytes stay in memory; never written to disk.

### 4.7 intel (optional)
- Enabled only with `vt=True` and `VT_API_KEY` set. Uses VirusTotal v3
  `/files/{sha256}` and `/urls/{id}` via `urllib`. Results attached to the
  attachment/URL entries; errors become info findings. Off by default.

### 4.8 scoring
- Score = min(100, Σ severity weights) with weights info 0, low 5, medium 15,
  high 30, critical 50.
- Verdict: 0–19 Clean, 20–49 Suspicious, ≥ 50 Likely phishing.
- Weights live in one table so they can be tuned and documented.

### 4.9 CLI
- `python -m phishkit analyze FILE [--json] [--live] [--vt] [--no-color]`.
- Exit code 0 clean, 1 suspicious, 2 likely phishing, 3 error — usable in
  scripts.

### 4.10 Web app
- `create_app(db_path)` factory; run with `python -m web` on `127.0.0.1:5000`.
- Routes: `GET /` upload form; `POST /analyze` → redirect to `/report/<id>`;
  `GET /report/<id>`; `GET /dashboard` (table of past analyses + verdict
  counts); `POST /api/analyze` (multipart file → JSON); `GET /api/report/<id>`.
- Upload form has checkboxes for live DNS and VirusTotal.
- Security: `MAX_CONTENT_LENGTH` 10 MB, `.eml` only, Jinja autoescape on, email
  HTML shown only as escaped source in a collapsible block, URLs defanged and
  never rendered as links, CSRF token on form posts, strict CSP header, no
  external assets.
- Storage: SQLite (`instance/phishkit.db`): id, created_at, filename, subject,
  from, score, verdict, report JSON.

## 5. Error handling

- Unparseable/empty input → `Report` with a parse-error finding; CLI exit 3
  only when the file cannot be read.
- DNS timeouts/NXDOMAIN → `temperror`/`none` results with explanation, never a
  crash. Per-query timeout 3 s.
- VirusTotal errors/rate limits → info finding, analysis continues.
- Web: friendly error page for bad uploads; 413 for oversize.

## 6. Testing

- `python -m unittest discover tests` — offline.
- `dnsutil` is replaced with a fake resolver in tests (fixed TXT/A/MX records).
- Live DKIM test uses a locally generated key pair: a sample is signed in the
  test with dkimpy and verified against the fake DNS record.
- Per-module unit tests plus end-to-end tests asserting each sample's verdict
  and key findings; Flask test-client tests for routes, API, escaping and size
  limit.

## 7. Samples and docs

- Crafted samples: credential-harvest (Microsoft 365 lookalike), PayPal
  lookalike with punycode/IP URLs, invoice with macro-enabled attachment +
  double extension, BEC CEO-fraud with Reply-To swap, HTML-smuggling
  attachment, and one legitimate newsletter. All benign: attachments are inert
  stand-ins that trigger detection (e.g. OOXML containing a dummy
  `vbaProject.bin`), never real malware.
- Public corpus: a few emails from a public dataset after a separate
  download confirmation.
- `README.md`: overview, setup, CLI/web usage, sample output, architecture,
  limitations.
- `docs/sample-analyses.md`: each sample's findings and analyst interpretation.
- `docs/defending-against-phishing.md`: SPF/DKIM/DMARC rollout (p=none →
  quarantine → reject), BIMI, secure email gateways, URL rewriting and
  time-of-click protection, attachment sandboxing, MFA/phishing-resistant
  auth (FIDO2), user awareness training and simulations, report-phish button,
  SOC triage playbook and incident response.

## 8. Known limitations

- Live DKIM may fail on old emails because the sender rotated keys; reported as
  "key unavailable".
- Organisational domain uses a built-in list of common multi-label public
  suffixes, not the full PSL.
- SPF evaluation does not support the `exists` and `ptr` mechanisms or macro
  expansion; a record that needs them evaluates to `neutral` with a note.
- Heuristics produce false positives; the score is triage guidance, not proof.
