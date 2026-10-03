"""The single place PhishKit touches DNS. Tests swap in a fake resolver with the same methods."""

from __future__ import annotations

from typing import Protocol

LOOKUP_TIMEOUT = 3.0


class DNSError(Exception):
    """kind is one of: 'nxdomain' (name/record does not exist), 'timeout', 'error'."""

    def __init__(self, kind: str, message: str = ""):
        super().__init__(message or kind)
        self.kind = kind


class Resolver(Protocol):
    def txt(self, name: str) -> list[str]: ...
    def a(self, name: str) -> list[str]: ...
    def aaaa(self, name: str) -> list[str]: ...
    def mx(self, name: str) -> list[str]: ...


class DnsPythonResolver:
    """Real resolver backed by dnspython."""

    def __init__(self, timeout: float = LOOKUP_TIMEOUT):
        import dns.resolver

        self._dns = dns
        self._resolver = dns.resolver.Resolver()
        self._resolver.lifetime = timeout
        self._resolver.timeout = timeout

    def _query(self, name: str, rtype: str):
        import dns.exception
        import dns.resolver

        try:
            return self._resolver.resolve(name, rtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            raise DNSError("nxdomain", f"no {rtype} record for {name}") from None
        except dns.exception.Timeout:
            raise DNSError("timeout", f"{rtype} lookup for {name} timed out") from None
        except dns.exception.DNSException as exc:
            raise DNSError("error", f"{rtype} lookup for {name} failed: {exc}") from None

    def txt(self, name: str) -> list[str]:
        return [b"".join(r.strings).decode("utf-8", "replace") for r in self._query(name, "TXT")]

    def a(self, name: str) -> list[str]:
        return [r.address for r in self._query(name, "A")]

    def aaaa(self, name: str) -> list[str]:
        return [r.address for r in self._query(name, "AAAA")]

    def mx(self, name: str) -> list[str]:
        return [str(r.exchange).rstrip(".") for r in self._query(name, "MX")]


def default_resolver() -> Resolver:
    return DnsPythonResolver()
