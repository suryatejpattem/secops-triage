"""Streaming parsers for Zeek newline-delimited JSON logs."""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from secops_triage.models import Indicator, IndicatorType


@dataclass
class ReadStats:
    """What a read saw. Skipped lines are counted, never silently lost."""

    lines: int = 0
    skipped: int = 0


def read_ndjson(path: Path, stats: ReadStats | None = None) -> Iterator[dict[str, Any]]:
    """Yield one dict per line. Constant memory, regardless of file size.

    Malformed lines are skipped rather than fatal -- one corrupt line in a
    40 GB log must not cost you the other 40 GB -- but every skip is counted
    in `stats`, so a run that skipped half its input can't look like success.
    """
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            if stats is not None:
                stats.lines += 1
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                obj = None
            if isinstance(obj, dict):
                yield obj
            elif stats is not None:
                stats.skipped += 1  # bad JSON, or valid JSON that isn't a record


def ip_type(value: str) -> IndicatorType | None:
    """IPV4 or IPV6 for a valid address; None for anything else."""
    try:
        version = ipaddress.ip_address(value).version
    except ValueError:
        return None
    return IndicatorType.IPV4 if version == 4 else IndicatorType.IPV6


def _name(value: Any) -> str | None:
    """Normalise a hostname: lower-case, no trailing dot. None if unusable."""
    if not isinstance(value, str):
        return None
    name = value.strip().lower().rstrip(".")
    return name or None


def extract_from_conn(
    path: Path, stats: ReadStats | None = None
) -> Iterator[Indicator]:
    """Destination IPs from a Zeek conn.log."""
    for rec in read_ndjson(path, stats):
        dst = rec.get("id.resp_h")
        kind = ip_type(dst) if isinstance(dst, str) else None
        if kind is None:
            continue
        yield Indicator(
            value=dst,
            type=kind,
            source="conn.log",
            context={
                "port": str(rec.get("id.resp_p", "")),
                "service": str(rec.get("service") or "unknown"),
            },
        )


def extract_from_dns(path: Path, stats: ReadStats | None = None) -> Iterator[Indicator]:
    """Queried domain names from a Zeek dns.log."""
    for rec in read_ndjson(path, stats):
        name = _name(rec.get("query"))
        if name:
            yield Indicator(value=name, type=IndicatorType.DOMAIN, source="dns.log")


def extract_from_ssl(path: Path, stats: ReadStats | None = None) -> Iterator[Indicator]:
    """TLS SNI server names from a Zeek ssl.log."""
    for rec in read_ndjson(path, stats):
        name = _name(rec.get("server_name"))
        if name:
            yield Indicator(value=name, type=IndicatorType.DOMAIN, source="ssl.log")
