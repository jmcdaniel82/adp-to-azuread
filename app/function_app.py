"""Thin Azure Functions entrypoints wired to service modules."""

from __future__ import annotations

from .azure_compat import func
from .export_routes import export_adp_data_handler, process_request_handler
from .provisioning import run_scheduled_provision_new_hires
from .updates import run_scheduled_update_existing_users

app = func.FunctionApp()


@app.schedule(schedule="0 */15 * * * *", arg_name="mytimer", run_on_startup=True)
def scheduled_provision_new_hires(mytimer: func.TimerRequest):
    """Provision AD accounts for recent hires."""
    run_scheduled_provision_new_hires(mytimer)


@app.schedule(schedule="0 0 * * * *", arg_name="mytimer", run_on_startup=False)
def scheduled_update_existing_users(mytimer: func.TimerRequest):
    """Update existing AD accounts from ADP data."""
    run_scheduled_update_existing_users(mytimer)


@app.function_name(name="process_request")
@app.route(route="process", methods=["POST"])
def process_request(req: func.HttpRequest) -> func.HttpResponse:
    """Expose worker payload diagnostics endpoint."""
    return process_request_handler(req)


@app.function_name(name="export_adp_data")
@app.route(route="export", methods=["GET"])
def export_adp_data(req: func.HttpRequest) -> func.HttpResponse:
    """Expose ADP-vs-AD mapping diagnostics endpoint."""
    return export_adp_data_handler(req)
