"""A compact SPF evaluator (RFC 7208) for re-checking an email's sending IP against DNS.

Supported: ip4, ip6, a, mx, include, all, redirect=, qualifiers and the 10-lookup limit.
Not supported: exists, ptr and macro expansion; records that need them evaluate to neutral.
"""

from __future__ import annotations

import ipaddress

from .dnsutil import DNSError

MAX_LOOKUPS = 10
QUALIFIERS = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}


class _SpfAbort(Exception):
    def __init__(self, result: str, detail: str):
        super().__init__(detail)
        self.result = result
        self.detail = detail


class _Evaluator:
    def __init__(self, ip: str, resolver):
        self.ip = ipaddress.ip_address(ip)
        self.resolver = resolver
        self.lookups = 0

    def _count_lookup(self):
        self.lookups += 1
        if self.lookups > MAX_LOOKUPS:
            raise _SpfAbort("permerror", f"more than {MAX_LOOKUPS} DNS lookups (possible include loop)")

    def _record(self, domain: str) -> str | None:
        try:
            txts = self.resolver.txt(domain)
        except DNSError as exc:
            if exc.kind == "nxdomain":
                return None
            raise _SpfAbort("temperror", f"DNS {exc.kind} looking up SPF for {domain}") from None
        records = [t for t in txts if t.lower().split()[:1] == ["v=spf1"]]
        if len(records) > 1:
            raise _SpfAbort("permerror", f"{domain} publishes more than one SPF record")
        return records[0] if records else None

    def _addresses(self, domain: str) -> list[str]:
        out = []
        for lookup in (self.resolver.a, self.resolver.aaaa):
            try:
                out.extend(lookup(domain))
            except DNSError as exc:
                if exc.kind != "nxdomain":
                    raise _SpfAbort("temperror", f"DNS {exc.kind} resolving {domain}") from None
        return out

    def _in_network(self, address: str, cidr4: int | None, cidr6: int | None) -> bool:
        try:
            addr = ipaddress.ip_address(address)
        except ValueError:
            return False
        if addr.version != self.ip.version:
            return False
        prefix = cidr4 if addr.version == 4 else cidr6
        if prefix is None:
            return addr == self.ip
        return self.ip in ipaddress.ip_network(f"{addr}/{prefix}", strict=False)

    @staticmethod
    def _split_cidr(spec: str, default_domain: str) -> tuple[str, int | None, int | None]:
        """Parse 'domain/24//64' style arguments of a and mx."""
        cidr4 = cidr6 = None
        if "//" in spec:
            spec, c6 = spec.split("//", 1)
            cidr6 = int(c6)
        if "/" in spec:
            spec, c4 = spec.split("/", 1)
            cidr4 = int(c4)
        return (spec or default_domain), cidr4, cidr6

    def check(self, domain: str, depth: int = 0) -> tuple[str, str]:
        record = self._record(domain)
        if record is None:
            return "none", f"{domain} publishes no SPF record"

        redirect = None
        for term in record.split()[1:]:
            lowered = term.lower()
            if lowered.startswith("redirect="):
                redirect = term.split("=", 1)[1]
                if "%{" in redirect:
                    raise _SpfAbort("neutral", f"SPF macros in {domain}'s record are not supported by this tool")
                continue
            if "=" in lowered and ":" not in lowered.split("=", 1)[0]:
                continue  # other modifiers such as exp= never affect the result
            if "%{" in term:
                # Unsupported features end the whole evaluation as neutral (not "no match"),
                # so an include that needs them cannot fall through to the parent's -all.
                raise _SpfAbort("neutral", f"SPF macros in {domain}'s record are not supported by this tool")

            qualifier = "+"
            if term[0] in QUALIFIERS:
                qualifier, term = term[0], term[1:]
            result = QUALIFIERS[qualifier]
            mech, _, arg = term.partition(":")
            mech = mech.lower()
            # "a/24" and "mx//64" carry their CIDR in the mechanism name itself.
            base = mech.split("/")[0]
            spec = arg if arg else mech[len(base):]

            if mech == "all":
                return result, f"matched '{qualifier}all' in {domain}'s record"
            if mech in ("ip4", "ip6"):
                try:
                    network = ipaddress.ip_network(arg, strict=False)
                except ValueError:
                    raise _SpfAbort("permerror", f"invalid {mech} value '{arg}' in {domain}") from None
                if self.ip.version == network.version and self.ip in network:
                    return result, f"{self.ip} matched {mech}:{arg} in {domain}'s record"
            elif base == "a":
                self._count_lookup()
                target, c4, c6 = self._split_cidr(spec, domain)
                if any(self._in_network(a, c4, c6) for a in self._addresses(target)):
                    return result, f"{self.ip} matched the A record of {target}"
            elif base == "mx":
                self._count_lookup()
                target, c4, c6 = self._split_cidr(spec, domain)
                try:
                    hosts = self.resolver.mx(target)
                except DNSError as exc:
                    if exc.kind != "nxdomain":
                        raise _SpfAbort("temperror", f"DNS {exc.kind} resolving MX for {target}") from None
                    hosts = []
                for host in hosts[:10]:
                    if any(self._in_network(a, c4, c6) for a in self._addresses(host)):
                        return result, f"{self.ip} matched MX host {host} of {target}"
            elif mech == "include":
                self._count_lookup()
                inner, inner_detail = self.check(arg, depth + 1)
                if inner == "pass":
                    return result, f"include:{arg} passed ({inner_detail})"
                if inner == "temperror":
                    raise _SpfAbort("temperror", inner_detail)
                if inner in ("permerror", "none"):
                    raise _SpfAbort("permerror", f"include:{arg} -> {inner} ({inner_detail})")
            elif mech in ("exists", "ptr"):
                raise _SpfAbort("neutral", f"the '{mech}' mechanism in {domain}'s record is not supported by this tool")
            else:
                raise _SpfAbort("permerror", f"unknown mechanism '{term}' in {domain}'s record")

        if redirect:
            self._count_lookup()
            result, detail = self.check(redirect, depth + 1)
            if result == "none":
                raise _SpfAbort("permerror", f"redirect target {redirect} has no SPF record")
            return result, f"via redirect={redirect}: {detail}"
        return "neutral", f"no mechanism in {domain}'s record matched {self.ip}"


def check_spf(ip: str, domain: str, resolver) -> tuple[str, str]:
    """Evaluate SPF for (ip, domain). Returns (result, human-readable detail)."""
    if not ip or not domain:
        return "none", "originating IP or envelope domain unknown"
    try:
        return _Evaluator(ip, resolver).check(domain.lower().rstrip("."))
    except _SpfAbort as abort:
        return abort.result, abort.detail
    except ValueError as exc:
        return "permerror", f"could not evaluate SPF: {exc}"
