"""Fail when a deployed Function App is missing expected indexed functions."""

from __future__ import annotations

import json
import os
import subprocess
import sys


def _run_az(*args: str) -> str:
    completed = subprocess.run(
        ["az", *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def main() -> int:
    app_name = os.environ["FUNCTIONAPP_NAME"]
    expected_names = {
        name.strip()
        for name in os.environ.get(
            "EXPECTED_FUNCTIONS",
            "diagnostics,scheduled_last_30_day_termed_report,scheduled_provision_new_hires,scheduled_update_existing_users",
        ).split(",")
        if name.strip()
    }
    resource_group = os.environ.get("FUNCTIONAPP_RESOURCE_GROUP") or _run_az(
        "functionapp",
        "show",
        "--name",
        app_name,
        "--query",
        "resourceGroup",
        "-o",
        "tsv",
    )
    raw = _run_az("functionapp", "function", "list", "-g", resource_group, "-n", app_name, "-o", "json")
    functions = json.loads(raw or "[]")
    indexed_names = {item["name"].split("/")[-1] for item in functions if item.get("name")}

    if not indexed_names:
        print(f"No functions indexed for {app_name} in resource group {resource_group}.", file=sys.stderr)
        return 1

    missing = sorted(expected_names - indexed_names)
    if missing:
        print(
            f"Missing indexed functions for {app_name}: {', '.join(missing)}; "
            f"found={', '.join(sorted(indexed_names))}",
            file=sys.stderr,
        )
        return 1

    print(f"Indexed functions for {app_name}: {', '.join(sorted(indexed_names))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
