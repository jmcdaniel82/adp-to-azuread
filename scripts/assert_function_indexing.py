"""Fail when a deployed Function App is missing expected indexed functions."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys


def _run_az(*args: str) -> str:
    az_executable = shutil.which("az") or shutil.which("az.cmd") or "az"
    completed = subprocess.run(
        [az_executable, *args],
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.strip() or completed.stdout.strip() or "unknown az error"
        raise RuntimeError(f"az {' '.join(args)} failed: {stderr}")
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
        "resource",
        "list",
        "--name",
        app_name,
        "--resource-type",
        "Microsoft.Web/sites",
        "--query",
        "[0].resourceGroup",
        "-o",
        "tsv",
    )
    if not resource_group:
        print(f"Could not resolve resource group for Function App {app_name}.", file=sys.stderr)
        return 1
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
