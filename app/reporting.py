"""Cross-cutting reporting/statistics helpers."""

from __future__ import annotations

from typing import Optional


def inc_stat(stats: Optional[dict[str, int]], key: str, delta: int = 1) -> None:
    """Increment one summary counter when stats dictionary is provided."""
    if stats is None:
        return
    stats[key] = int(stats.get(key, 0) or 0) + delta
