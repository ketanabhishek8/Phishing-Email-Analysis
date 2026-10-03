"""Sender consistency: does everything that claims to identify the sender agree?"""

from __future__ import annotations

import re
from email.utils import parseaddr

from .domains import (
    FREEMAIL, brand_in, decode_idn, domain_of, is_punycode, legit_brand_for, lookalike_of,
    org_domain, same_org,
)
from .models import Finding, Severity
from .parser import ParsedEmail
from .textsafe import BIDI_CONTROLS, reveal

CATEGORY = "sender"

ROLE_WORDS = re.compile(
    r"\b(help ?desk|it support|it department|service desk|payroll|human resources|hr department|"
    r"accounts? payable|finance|billing|ceo|cfo|chief executive|administrator|admin team|"
    r"security team|it team|tech support|customer support|support team|webmaster|postmaster)\b",
    re.I,
)
_EMAIL_IN_TEXT = re.compile(r"(?<![\w.+'-])[\w.+'-]+@[\w-]+(?:\.[\w-]+)+")


def _msgid_domain(message_id: str) -> str:
    match = re.search(r"@([^>\s]+)", message_id or "")
    return match.group(1).lower().strip(".") if match else ""


def parse_from(value: str) -> tuple[str, str]:
    """Split a From header into (display name, address), tolerating malformed headers.

    Phishers sometimes break the syntax on purpose (e.g. 'Brand team ,_<x@evil>') so that
    strict parsers return nothing; fall back to the last address in angle brackets.
    """
    name, address = parseaddr(value or "")
    if "@" in address:
        return name, address
    match = re.search(r"<\s*([^<>\s]+@[^<>\s]+)\s*>\s*$", value or "")
    if match:
        display = value[: match.start()].strip().strip(",_ ").strip('"').strip(",_ ")
        return display, match.group(1)
    addresses = _EMAIL_IN_TEXT.findall(value or "")
    return (name, addresses[-1]) if addresses else (name, address)


def analyze_senders(email: ParsedEmail) -> tuple[dict, list[Finding]]:
    findings: list[Finding] = []
    from_name, from_address = parse_from(email.from_)
    from_domain = domain_of(from_address)
    reply_to = email.get("Reply-To") or ""
    return_path = email.get("Return-Path") or ""
    sender = email.get("Sender") or ""
    reply_domain = domain_of(reply_to)
    return_domain = domain_of(return_path)
    sender_domain = domain_of(sender)
    msgid_domain = _msgid_domain(email.message_id)

    section = {
        "from_name": from_name,
        "from_address": from_address,
        "from_domain": from_domain,
        "from_domain_decoded": decode_idn(from_domain) if is_punycode(from_domain) else from_domain,
        "reply_to": reply_to,
        "reply_to_domain": reply_domain,
        "return_path": return_path,
        "return_path_domain": return_domain,
        "sender": sender,
        "message_id_domain": msgid_domain,
        "mismatches": [],
        "lookalike": None,
    }

    hidden = [(name, value) for name, value in (("Subject", email.subject), ("From", email.from_),
                                                 ("Reply-To", reply_to)) if BIDI_CONTROLS.search(value or "")]
    if hidden:
        findings.append(Finding(
            CATEGORY, Severity.MEDIUM, "Hidden text-direction characters in headers",
            "Invisible Unicode direction controls reorder how text is displayed. Legitimate mail "
            "has no reason to use them in these headers; attackers use them to disguise names and "
            "subjects.", "; ".join(f"{n}: {reveal(v)}" for n, v in hidden)[:300],
        ))

    if not from_domain:
        findings.append(Finding(CATEGORY, Severity.MEDIUM, "Missing From address",
                                "The email has no usable From address, which legitimate senders always set.",
                                email.from_))
        return section, findings

    if reply_domain and not same_org(reply_domain, from_domain):
        section["mismatches"].append("reply_to")
        extra = " Replies go to a free webmail account." if org_domain(reply_domain) in FREEMAIL else ""
        findings.append(Finding(
            CATEGORY, Severity.HIGH, "Reply-To differs from From",
            "Replies will go to a different organisation than the visible sender. This is the "
            "core trick in business email compromise (BEC) and invoice fraud." + extra,
            f"From: {from_address} | Reply-To: {reply_to}",
        ))

    if return_domain and not same_org(return_domain, from_domain):
        section["mismatches"].append("return_path")
        findings.append(Finding(
            CATEGORY, Severity.LOW, "Return-Path differs from From",
            "The envelope sender (where bounces go) is a different domain. Common for legitimate "
            "bulk-mail services, but also how spoofers pass SPF for their own domain while showing "
            "someone else's in From. DMARC alignment is the decisive check.",
            f"From: {from_address} | Return-Path: {return_path}",
        ))

    if sender_domain and not same_org(sender_domain, from_domain):
        section["mismatches"].append("sender")
        findings.append(Finding(CATEGORY, Severity.LOW, "Sender header differs from From",
                                "The Sender header names a different domain than From.",
                                f"Sender: {sender}"))

    if msgid_domain and not same_org(msgid_domain, from_domain):
        section["mismatches"].append("message_id")
        findings.append(Finding(
            CATEGORY, Severity.LOW, "Message-ID domain differs from From",
            "The Message-ID was generated by a different domain's mail system than the one in From.",
            f"Message-ID domain: {msgid_domain}",
        ))

    lookalike = lookalike_of(from_domain)
    if lookalike:
        section["lookalike"] = lookalike
        shown = decode_idn(from_domain)
        findings.append(Finding(
            CATEGORY, Severity.CRITICAL, "Lookalike sender domain",
            f"The sender domain '{shown}' imitates {lookalike} using look-alike characters, "
            "a typo or brand-plus-keyword construction.",
            f"From domain: {from_domain}",
        ))

    embedded = [a for a in _EMAIL_IN_TEXT.findall(from_name or "")
                if not same_org(domain_of(a), from_domain)]
    if embedded:
        findings.append(Finding(
            CATEGORY, Severity.HIGH, "Display name contains a different email address",
            "Mail clients often show only the display name, so the recipient sees the embedded "
            "address instead of the real sender.",
            f"Display name: {from_name} | Actual address: {from_address}",
        ))

    claimed_brand = brand_in(from_name)
    actual_brand = legit_brand_for(from_domain)
    if claimed_brand and claimed_brand != actual_brand and not lookalike:
        findings.append(Finding(
            CATEGORY, Severity.HIGH, "Display name impersonates a brand",
            f"The display name claims to be {claimed_brand.title()} but the address is at "
            f"{from_domain}, which {claimed_brand.title()} does not use.",
            f"{from_name} <{from_address}>",
        ))
    elif org_domain(from_domain) in FREEMAIL and ROLE_WORDS.search(from_name or ""):
        findings.append(Finding(
            CATEGORY, Severity.MEDIUM, "Free webmail account posing as an organisation",
            "The display name suggests an internal team or executive, but the message comes from "
            "a free webmail account that anyone can register.",
            f"{from_name} <{from_address}>",
        ))

    return section, findings
