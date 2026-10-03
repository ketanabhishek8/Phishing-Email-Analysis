"""Turn raw .eml bytes into a ParsedEmail that the analysis modules can work with.

The parser is deliberately forgiving: phishing emails are often malformed on
purpose, so every step falls back to a best-effort value instead of raising.
"""

from __future__ import annotations

import email
import ipaddress
import re
from dataclasses import dataclass, field
from email import policy
from email.message import Message


@dataclass
class RawAttachment:
    filename: str
    content_type: str
    payload: bytes


@dataclass
class Hop:
    """One Received: header, i.e. one server-to-server handoff."""

    from_host: str
    by_host: str
    ip: str
    timestamp: str
    raw: str


@dataclass
class ParsedEmail:
    raw: bytes
    headers: list[tuple[str, str]] = field(default_factory=list)
    text_body: str = ""
    html_body: str = ""
    attachments: list[RawAttachment] = field(default_factory=list)
    received: list[Hop] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)

    def get_all(self, name: str) -> list[str]:
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]

    def get(self, name: str) -> str | None:
        values = self.get_all(name)
        return values[0] if values else None

    @property
    def subject(self) -> str:
        return self.get("Subject") or ""

    @property
    def from_(self) -> str:
        return self.get("From") or ""

    @property
    def to(self) -> str:
        return self.get("To") or ""

    @property
    def date(self) -> str:
        return self.get("Date") or ""

    @property
    def message_id(self) -> str:
        return self.get("Message-ID") or ""


_WS = re.compile(r"\s+")


def _clean(value: str) -> str:
    """Unfold a header value and collapse runs of whitespace."""
    return _WS.sub(" ", str(value)).strip()


def _read_headers(msg: Message, errors: list[str]) -> list[tuple[str, str]]:
    headers = []
    # Read the raw (name, value) pairs so one malformed header cannot break the rest.
    for key, value in msg._headers:
        try:
            decoded = str(msg.policy.header_fetch_parse(key, value))
        except Exception:  # malformed encoded-words etc.
            errors.append(f"Could not decode header {key!r}")
            decoded = str(value)
        headers.append((key, _clean(decoded)))
    return headers


def _decode_text(part: Message) -> str:
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        for charset in (part.get_content_charset() or "", "utf-8", "latin-1"):
            try:
                return payload.decode(charset or "utf-8")
            except (LookupError, UnicodeDecodeError):
                continue
        return payload.decode("utf-8", "replace")


_IP_BRACKET = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]")
_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_FROM = re.compile(r"\bfrom\s+([^\s;()]+)", re.I)
_BY = re.compile(r"\bby\s+([^\s;()]+)", re.I)


def _valid_ip(candidate: str) -> str:
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return ""


def parse_received(value: str) -> Hop:
    ip = ""
    for candidate in _IP_BRACKET.findall(value):
        ip = _valid_ip(candidate)
        if ip:
            break
    if not ip:
        # Fall back to a bare IPv4 inside the "from" clause, before " by ".
        from_clause = re.split(r"\bby\b", value, maxsplit=1, flags=re.I)[0]
        for candidate in _IPV4.findall(from_clause):
            ip = _valid_ip(candidate)
            if ip:
                break
    from_match = _FROM.search(value)
    by_match = _BY.search(value)
    timestamp = value.rsplit(";", 1)[1].strip() if ";" in value else ""
    return Hop(
        from_host=from_match.group(1) if from_match else "",
        by_host=by_match.group(1) if by_match else "",
        ip=ip,
        timestamp=timestamp,
        raw=value,
    )


def parse_email(raw: bytes) -> ParsedEmail:
    parsed = ParsedEmail(raw=raw)
    if not raw or not raw.strip():
        parsed.parse_errors.append("Input is empty")
        return parsed

    try:
        msg = email.message_from_bytes(raw, policy=policy.default)
    except Exception as exc:  # pragma: no cover - stdlib parser rarely raises
        parsed.parse_errors.append(f"Could not parse message: {exc}")
        return parsed

    parsed.parse_errors.extend(str(d) for d in msg.defects)
    parsed.headers = _read_headers(msg, parsed.parse_errors)
    parsed.received = [parse_received(v) for v in parsed.get_all("Received")]

    text_parts, html_parts = [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        try:
            filename = part.get_filename()
        except Exception:
            filename = None
        disposition = (part.get_content_disposition() or "").lower()
        ctype = part.get_content_type()

        if filename or disposition == "attachment":
            payload = part.get_payload(decode=True) or b""
            parsed.attachments.append(
                RawAttachment(filename=_clean(filename or "(unnamed)"), content_type=ctype, payload=payload)
            )
        elif ctype == "text/plain":
            text_parts.append(_decode_text(part))
        elif ctype == "text/html":
            html_parts.append(_decode_text(part))

    parsed.text_body = "\n".join(text_parts)
    parsed.html_body = "\n".join(html_parts)
    return parsed
