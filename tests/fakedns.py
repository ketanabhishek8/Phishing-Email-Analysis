"""An in-memory resolver used in tests instead of real DNS."""

from phishkit.dnsutil import DNSError


class FakeResolver:
    """records: {("TXT", "example.com"): ["v=spf1 -all"], ...}
    A value of "timeout" (string) makes that lookup raise a timeout."""

    def __init__(self, records=None):
        self.records = {(t.upper(), n.lower().rstrip(".")): v for (t, n), v in (records or {}).items()}
        self.queries = []

    def _lookup(self, rtype, name):
        key = (rtype, name.lower().rstrip("."))
        self.queries.append(key)
        value = self.records.get(key)
        if value == "timeout":
            raise DNSError("timeout", f"{rtype} {name} timed out")
        if value is None:
            raise DNSError("nxdomain", f"no {rtype} record for {name}")
        return list(value)

    def txt(self, name):
        return self._lookup("TXT", name)

    def a(self, name):
        return self._lookup("A", name)

    def aaaa(self, name):
        return self._lookup("AAAA", name)

    def mx(self, name):
        return self._lookup("MX", name)
