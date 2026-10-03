"""Hash every attachment and flag the tricks used to deliver malware.

Attachment bytes are only ever held in memory: nothing is written to disk or executed.
"""

from __future__ import annotations

import hashlib
import io
import re
import zipfile

from .models import Finding, Severity
from .parser import ParsedEmail

CATEGORY = "attachments"

EXECUTABLE_EXT = {
    "exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "wsh", "hta",
    "ps1", "psm1", "msi", "msp", "jar", "dll", "cpl", "reg", "lnk", "chm", "xll", "appx",
    "msix", "appinstaller", "url", "scf", "application", "gadget", "inf",
}
CONTAINER_EXT = {"iso", "img", "vhd", "vhdx"}  # used to dodge Mark-of-the-Web
MACRO_EXT = {"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "sldm"}
OTHER_RISKY_EXT = {"one", "iqy", "slk", "svg"}
RISKY_EXT = EXECUTABLE_EXT | CONTAINER_EXT | MACRO_EXT | OTHER_RISKY_EXT
DECOY_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png",
             "gif", "rtf", "csv", "html", "htm", "zip", "mp3", "mp4", "wav"}
ARCHIVE_TYPES = {"zip", "rar", "7z", "gzip"}

# Extension -> detected types that are consistent with it.
EXPECTED_TYPES = {
    "pdf": {"pdf"}, "docx": {"ooxml"}, "xlsx": {"ooxml"}, "pptx": {"ooxml"},
    "docm": {"ooxml"}, "xlsm": {"ooxml"}, "pptm": {"ooxml"},
    "doc": {"ole2", "rtf"}, "xls": {"ole2"}, "ppt": {"ole2"}, "msg": {"ole2"},
    "zip": {"zip", "ooxml"}, "rar": {"rar"}, "7z": {"7z"}, "gz": {"gzip"},
    "jpg": {"jpeg"}, "jpeg": {"jpeg"}, "png": {"png"}, "gif": {"gif"},
    "html": {"html", "text"}, "htm": {"html", "text"}, "txt": {"text"}, "csv": {"text"},
    "rtf": {"rtf"}, "iso": {"iso"}, "img": {"iso", "unknown"},
}
# Detected types that are dangerous when they appear under an innocent extension.
DANGEROUS_TYPES = {"pe", "elf", "lnk", "html", "ole2", "iso", "script", "onenote"}

BIDI_CONTROLS = re.compile("[‪-‮⁦-⁩‎‏]")

_SMUGGLING = re.compile(rb"(?i)(atob\s*\(|new\s+Blob|createObjectURL|msSaveOrOpenBlob|\.download\s*=|"
                        rb"fromCharCode|unescape\s*\(|base64,)")
_SCRIPT = re.compile(rb"(?i)<script")
_PASSWORD_FORM = re.compile(rb"(?i)<form[\s\S]*?type\s*=\s*['\"]?password")
_PDF_ACTIVE = re.compile(rb"/(JavaScript|JS|Launch|OpenAction|EmbeddedFile)\b")


def detect_type(payload: bytes) -> str:
    """Identify a file from its leading bytes (magic numbers), ignoring its name."""
    head = payload[:16]
    if head.startswith(b"MZ"):
        return "pe"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head.startswith(b"%PDF"):
        return "pdf"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole2"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        try:
            names = zipfile.ZipFile(io.BytesIO(payload)).namelist()
        except zipfile.BadZipFile:
            return "zip"
        return "ooxml" if "[Content_Types].xml" in names else "zip"
    if head.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        return "lnk"
    if head.startswith(b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d"):
        return "onenote"
    if head.startswith(b"{\\rtf"):
        return "rtf"
    if head.startswith(b"\x89PNG"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if payload[0x8001:0x8006] == b"CD001":
        return "iso"
    sample = payload[:2048].lstrip().lower()
    if sample.startswith((b"<!doctype html", b"<html", b"<head", b"<body", b"<script", b"<svg")) or b"<html" in sample[:512]:
        return "html"
    try:
        payload[:4096].decode("utf-8")
        return "text"
    except UnicodeDecodeError:
        return "unknown"


def _extensions(filename: str) -> list[str]:
    name = BIDI_CONTROLS.sub("", filename).strip().lower()
    return [p for p in name.split(".")[1:] if p and len(p) <= 12]


def _zip_info(payload: bytes) -> tuple[list[str], bool]:
    try:
        zf = zipfile.ZipFile(io.BytesIO(payload))
        infos = zf.infolist()
    except (zipfile.BadZipFile, ValueError, OSError):
        return [], False
    return [i.filename for i in infos][:50], any(i.flag_bits & 0x1 for i in infos)


def _analyze_one(filename: str, content_type: str, payload: bytes) -> tuple[dict, list[Finding]]:
    findings: list[Finding] = []
    flags: list[str] = []
    detected = detect_type(payload)
    exts = _extensions(filename)
    ext = exts[-1] if exts else ""
    entry = {
        "filename": filename,
        "content_type": content_type,
        "size": len(payload),
        "md5": hashlib.md5(payload).hexdigest(),
        "sha1": hashlib.sha1(payload).hexdigest(),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "detected_type": detected,
        "extension": ext,
        "flags": flags,
        "archive_members": [],
    }

    def add(flag, severity, title, detail):
        flags.append(flag)
        findings.append(Finding(CATEGORY, severity, title, detail, filename))

    if BIDI_CONTROLS.search(filename):
        add("rtlo", Severity.CRITICAL, "Filename uses right-to-left override",
            "Invisible Unicode direction characters reverse part of the name so 'invoice‮fdp.exe' "
            "displays as 'invoiceexe.pdf'.")
    if len(exts) >= 2 and ext in RISKY_EXT and exts[-2] in DECOY_EXT:
        add("double_extension", Severity.CRITICAL, "Double file extension",
            f"The name ends in '.{exts[-2]}.{ext}': Windows hides known extensions by default, so the "
            f"recipient sees a harmless-looking '.{exts[-2]}' file that is really '.{ext}'.")
    if ext in RISKY_EXT:
        kind = ("macro-enabled Office document" if ext in MACRO_EXT else
                "disk image that bypasses Mark-of-the-Web protections" if ext in CONTAINER_EXT else
                "executable or script" if ext in EXECUTABLE_EXT else "file type abused for malware delivery")
        add("risky_extension", Severity.HIGH, "Risky attachment type",
            f"'.{ext}' is a {kind}. Legitimate business email rarely needs to send these.")

    expected = EXPECTED_TYPES.get(ext)
    if expected and detected not in expected and detected != "unknown" and (
        detected in DANGEROUS_TYPES or detected in ARCHIVE_TYPES or detected == "pdf"
    ):
        add("type_mismatch", Severity.HIGH, "File content does not match its extension",
            f"The file is named '.{ext}' but its content is actually '{detected}'.")

    if detected == "ooxml":
        members, _ = _zip_info(payload)
        if any(m.lower().endswith("vbaproject.bin") for m in members):
            add("macros", Severity.HIGH, "Office document contains macros",
                "The document embeds a VBA project. Macros are the classic first stage of malware such "
                "as Emotet and Qakbot.")
    elif detected == "ole2" and (b"_VBA_PROJECT" in payload or b"VBA\x00" in payload or b"Macros" in payload):
        add("macros", Severity.HIGH, "Office document contains macros",
            "The legacy Office file contains a VBA macro project.")

    if detected == "zip":
        members, encrypted = _zip_info(payload)
        entry["archive_members"] = members
        if encrypted:
            add("encrypted_archive", Severity.MEDIUM, "Password-protected archive",
                "Encrypted archives cannot be scanned by email security gateways; the password is "
                "usually in the email body.")
        risky_members = [m for m in members if (_extensions(m) or [""])[-1] in RISKY_EXT]
        if risky_members:
            add("archive_contains_risky", Severity.HIGH, "Archive contains risky files",
                "Inside the archive: " + ", ".join(risky_members[:5]))

    if detected == "html" or ext in ("html", "htm", "shtml", "xhtml", "svg"):
        if _SCRIPT.search(payload) and _SMUGGLING.search(payload):
            add("html_smuggling", Severity.HIGH, "HTML smuggling attachment",
                "The HTML file contains script that builds a file in the browser (atob/Blob/download). "
                "This assembles malware on the victim's machine, past the email gateway.")
        if _PASSWORD_FORM.search(payload):
            add("credential_form", Severity.HIGH, "HTML attachment contains a login form",
                "A local HTML page with a password field is a credential-harvesting page that runs "
                "from the victim's disk, so URL filters never see it.")
        if not flags or flags == ["type_mismatch"]:
            add("html_attachment", Severity.MEDIUM, "HTML attachment",
                "HTML attachments open in the browser and are frequently used for phishing pages.")

    if detected == "pdf" and _PDF_ACTIVE.search(payload):
        add("pdf_active_content", Severity.MEDIUM, "PDF contains active content",
            "The PDF declares JavaScript, launch actions, auto-open actions or embedded files.")

    return entry, findings


def analyze_attachments(email: ParsedEmail) -> tuple[list[dict], list[Finding]]:
    entries, findings = [], []
    for attachment in email.attachments:
        entry, entry_findings = _analyze_one(attachment.filename, attachment.content_type, attachment.payload)
        entries.append(entry)
        findings.extend(entry_findings)
    return entries, findings
