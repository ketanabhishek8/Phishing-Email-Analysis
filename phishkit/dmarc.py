"""DMARC policy lookup and identifier alignment (RFC 7489)."""

from __future__ import annotations

from .dnsutil import DNSError
from .domains import normalise_domain, org_domain


def parse_record(record: str) -> dict:
    tags = {}
    for part in record.split(";"):
        key, sep, value = part.strip().partition("=")
        if sep:
            tags[key.strip().lower()] = value.strip()
    tags.setdefault("adkim", "r")
    tags.setdefault("aspf", "r")
    tags.setdefault("pct", "100")
    tags["p"] = tags.get("p", "none").lower()
    tags.setdefault("sp", tags["p"])
    return tags


def _lookup(domain: str, resolver) -> str | None:
    try:
        txts = resolver.txt(f"_dmarc.{domain}")
    except DNSError as exc:
        if exc.kind == "nxdomain":
            return None
        raise
    records = [t for t in txts if t.replace(" ", "").lower().startswith("v=dmarc1")]
    return records[0] if len(records) == 1 else None


def fetch_policy(from_domain: str, resolver) -> dict | None:
    """Find the DMARC policy for a From domain, falling back to its organisational domain.

    Raises DNSError for timeouts/server failures so callers can report temperror.
    """
    domain = normalise_domain(from_domain)
    if not domain:
        return None
    candidates = [domain]
    org = org_domain(domain)
    if org != domain:
        candidates.append(org)
    for candidate in candidates:
        record = _lookup(candidate, resolver)
        if record:
            policy = parse_record(record)
            policy["domain"] = candidate
            policy["record"] = record
            policy["inherited"] = candidate != domain
            return policy
    return None


def _aligned(domain: str, from_domain: str, mode: str) -> bool:
    domain, from_domain = normalise_domain(domain), normalise_domain(from_domain)
    if not domain or not from_domain:
        return False
    if mode == "s":
        return domain == from_domain
    return org_domain(domain) == org_domain(from_domain)


def alignment(from_domain: str, spf_domain: str, dkim_domains: list[str],
              adkim: str = "r", aspf: str = "r") -> dict:
    aligned_dkim = [d for d in dkim_domains if _aligned(d, from_domain, adkim)]
    return {
        "from_domain": from_domain,
        "spf_domain": spf_domain,
        "spf_aligned": _aligned(spf_domain, from_domain, aspf),
        "dkim_domains": list(dkim_domains),
        "dkim_aligned": bool(aligned_dkim),
        "aligned_dkim_domains": aligned_dkim,
        "mode": {"adkim": adkim, "aspf": aspf},
    }
