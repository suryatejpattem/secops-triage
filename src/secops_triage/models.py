"""Data structures shared across the tool."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class IndicatorType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"


@dataclass(frozen=True, slots=True)
class Indicator:
    """A single observable extracted from a log source."""

    value: str
    type: IndicatorType
    source: str  # which log file it came from
    count: int = 1
    context: dict[str, str] = field(default_factory=dict, compare=False)
