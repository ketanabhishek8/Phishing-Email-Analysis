"""Helpers for building .eml bytes inside tests."""

from email.message import EmailMessage

DEFAULT_HEADERS = {
    "From": "Alice <alice@example.com>",
    "To": "bob@example.org",
    "Subject": "Hello",
    "Date": "Fri, 02 Oct 2026 10:00:00 +0000",
    "Message-ID": "<abc123@example.com>",
}


def make_eml(headers=None, text="Hello Bob", html=None, attachments=(), extra=()):
    """Build an email. `extra` is a list of (name, value) headers prepended in order
    (first item ends up topmost, like Received/Authentication-Results)."""
    msg = EmailMessage()
    for name, value in extra:
        msg[name] = value
    merged = dict(DEFAULT_HEADERS)
    merged.update(headers or {})
    for name, value in merged.items():
        if value is not None:
            msg[name] = value
    msg.set_content(text)
    if html is not None:
        msg.add_alternative(html, subtype="html")
    for filename, payload, maintype, subtype in attachments:
        msg.add_attachment(payload, maintype=maintype, subtype=subtype, filename=filename)
    return msg.as_bytes()
