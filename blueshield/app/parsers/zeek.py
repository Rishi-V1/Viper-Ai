"""Zeek conn.log / dns.log parsing (spec section 6: "optional at first").

Not implemented in the minimum-viable version (spec section 15 scopes
milestones 1-5 around Suricata + auth logs only). Kept as a stub so the
ingestion layer has a stable place to add Zeek support without changing its
interface.
"""

from app.parsers.suricata import ParseResult


def parse_conn_log(text: str, source_label: str = "zeek.conn.log") -> ParseResult:
    raise NotImplementedError("Zeek conn.log parsing is a later milestone; not required for the MVP.")


def parse_dns_log(text: str, source_label: str = "zeek.dns.log") -> ParseResult:
    raise NotImplementedError("Zeek dns.log parsing is a later milestone; not required for the MVP.")
