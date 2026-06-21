"""Local, optional threat-intelligence matching (IOC watchlists).

Entirely file-based and offline: no cloud services, no API keys, no paid feeds.
An operator drops plain-text indicator lists on disk and points two environment
variables at them; until then every entry point here is a fast no-op, so the
feature costs nothing when unused.

Indicator file format (both lists):
    * one indicator per line
    * blank lines and lines beginning with '#' are ignored
    * inline trailing comments after whitespace + '#' are stripped

IP list (``IOC_IP_LIST_PATH``)      — individual IPv4/IPv6 addresses or CIDR ranges
Domain list (``IOC_DOMAIN_LIST_PATH``) — domains; a listed parent matches its
                                         subdomains (``evil.com`` matches
                                         ``login.evil.com``)

Files are cached by (path, mtime), so a long-running correlation daemon picks up
edits to the lists without a restart and without re-reading unchanged files.
"""

import ipaddress
import os
from pathlib import Path

# (path) -> (mtime, parsed_lines). Module-level so repeated sweeps reuse parsed
# content; keyed on mtime so an edited file is transparently reloaded.
_FILE_CACHE: dict[str, tuple[float, list[str]]] = {}


def _load_lines(path: str | None) -> list[str]:
    """Reads non-comment, non-blank lines from a file, with mtime caching."""
    if not path:
        return []
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return []
    cached = _FILE_CACHE.get(path)
    if cached and cached[0] == mtime:
        return cached[1]
    lines: list[str] = []
    try:
        for raw in Path(path).read_text(encoding="utf-8").splitlines():
            # Strip inline comments and surrounding whitespace.
            entry = raw.split("#", 1)[0].strip()
            if entry:
                lines.append(entry)
    except OSError:
        return []
    _FILE_CACHE[path] = (mtime, lines)
    return lines


class ThreatIntel:
    """Matches entities (IPs, domains) against local IOC watchlists."""

    def __init__(
        self,
        ip_indicators: set[str] | None = None,
        cidr_indicators: list | None = None,
        domain_indicators: set[str] | None = None,
    ):
        self._ips = ip_indicators or set()
        self._cidrs = cidr_indicators or []  # list[ip_network]
        self._domains = domain_indicators or set()

    @classmethod
    def from_files(
        cls, ip_path: str | None = None, domain_path: str | None = None
    ) -> "ThreatIntel":
        ips: set[str] = set()
        cidrs: list = []
        for entry in _load_lines(ip_path):
            if "/" in entry:
                try:
                    cidrs.append(ipaddress.ip_network(entry, strict=False))
                except ValueError:
                    continue  # skip malformed CIDR rather than fail the load
            else:
                try:
                    ips.add(str(ipaddress.ip_address(entry)))
                except ValueError:
                    continue
        domains = {d.lower().rstrip(".") for d in _load_lines(domain_path)}
        return cls(ips, cidrs, domains)

    @classmethod
    def from_env(cls) -> "ThreatIntel":
        return cls.from_files(
            ip_path=os.getenv("IOC_IP_LIST_PATH", "").strip() or None,
            domain_path=os.getenv("IOC_DOMAIN_LIST_PATH", "").strip() or None,
        )

    def has_indicators(self) -> bool:
        return bool(self._ips or self._cidrs or self._domains)

    def match_ip(self, value: str | None) -> str | None:
        """Returns the matching indicator (exact IP or CIDR string), else None."""
        if not value:
            return None
        try:
            addr = ipaddress.ip_address(value.strip())
        except ValueError:
            return None
        if str(addr) in self._ips:
            return str(addr)
        for net in self._cidrs:
            # Skip family mismatches (IPv4 addr vs IPv6 net) cheaply.
            if addr.version == net.version and addr in net:
                return str(net)
        return None

    def match_domain(self, value: str | None) -> str | None:
        """Returns the matching listed domain (exact or parent), else None."""
        if not value or not self._domains:
            return None
        host = value.strip().lower().rstrip(".")
        if not host:
            return None
        if host in self._domains:
            return host
        # Parent-domain match: 'login.evil.com' matches a listed 'evil.com'.
        labels = host.split(".")
        for i in range(1, len(labels)):
            parent = ".".join(labels[i:])
            if parent in self._domains:
                return parent
        return None

    def match(self, value: str | None) -> str | None:
        """Convenience: try IP then domain matching."""
        return self.match_ip(value) or self.match_domain(value)
