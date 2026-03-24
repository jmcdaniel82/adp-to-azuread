"""Shared env gating for opt-in live integration tests.

These tests are intentionally skipped unless the required live environment
variables are present. That keeps the default `pytest` run offline and safe.
"""

from __future__ import annotations

import os
from typing import Iterable

import pytest


def require_env(*names: str) -> dict[str, str]:
    """Return required environment variables or skip the current test module."""
    missing = [name for name in names if not os.getenv(name)]
    if missing:
        pytest.skip(
            "Skipping live integration tests; missing env vars: " + ", ".join(sorted(missing)),
            allow_module_level=True,
        )
    return {name: os.environ[name] for name in names}


def require_any(*names: str) -> dict[str, str]:
    """Return available env vars, skipping if none are present."""
    present = {name: os.environ[name] for name in names if os.getenv(name)}
    if not present:
        pytest.skip(
            "Skipping live integration tests; none of the optional env vars are set: "
            + ", ".join(names),
            allow_module_level=True,
        )
    return present


def require_all_of_groups(groups: Iterable[Iterable[str]]) -> dict[str, str]:
    """Validate a list of env groups and skip if any required group is incomplete."""
    merged: dict[str, str] = {}
    missing_groups: list[str] = []
    for group in groups:
        required = list(group)
        missing = [name for name in required if not os.getenv(name)]
        if missing:
            missing_groups.append("[" + ", ".join(missing) + "]")
            continue
        merged.update({name: os.environ[name] for name in required})
    if missing_groups:
        pytest.skip(
            "Skipping live integration tests; missing env vars in one or more groups: "
            + ", ".join(missing_groups),
            allow_module_level=True,
        )
    return merged

