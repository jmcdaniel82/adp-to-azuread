"""Thin Azure Functions entrypoints wired to service modules."""

from __future__ import annotations

import os

from .azure_compat import func
from .diagnostics_routes import diagnostics_handler
from .provisioning import run_scheduled_provision_new_hires
from .termination_report import run_scheduled_last_30_day_termed_report
from .updates import run_scheduled_update_existing_users

app = func.FunctionApp()
WEEKLY_TERMED_REPORT_SCHEDULE = os.getenv("TERMED_REPORT_SCHEDULE", "0 0 14 * * 1")


@app.schedule(schedule="0 */15 * * * *", arg_name="mytimer", run_on_startup=True)
def scheduled_provision_new_hires(mytimer: func.TimerRequest):
    """Provision AD accounts for recent hires."""
    run_scheduled_provision_new_hires(mytimer)


@app.schedule(schedule="0 0 * * * *", arg_name="mytimer", run_on_startup=False)
def scheduled_update_existing_users(mytimer: func.TimerRequest):
    """Update existing AD accounts from ADP data."""
    run_scheduled_update_existing_users(mytimer)


@app.schedule(schedule=WEEKLY_TERMED_REPORT_SCHEDULE, arg_name="mytimer", run_on_startup=False)
def scheduled_last_30_day_termed_report(mytimer: func.TimerRequest):
    """Email the weekly ADP termed report."""
    run_scheduled_last_30_day_termed_report(mytimer)


@app.function_name(name="diagnostics")
@app.route(route="diagnostics", methods=["GET"])
def diagnostics(req: func.HttpRequest) -> func.HttpResponse:
    """Expose diagnostics views for summary, diff, worker, and recent-hire lookups."""
    return diagnostics_handler(req)
