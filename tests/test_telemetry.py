import json
import logging

from app.telemetry import APP_TELEMETRY_PREFIX, StructuredLogTelemetrySink, new_run_id


def test_structured_log_telemetry_sink_emits_json_payload(caplog):
    sink = StructuredLogTelemetrySink()

    with caplog.at_level(logging.INFO):
        sink.emit(
            "job_run",
            {
                "job": "scheduled_update_existing_users",
                "run_id": "run-123",
                "dry_run": True,
            },
        )

    message = caplog.messages[-1]
    assert message.startswith(f"{APP_TELEMETRY_PREFIX} ")
    payload = json.loads(message[len(APP_TELEMETRY_PREFIX) + 1 :])
    assert payload["event"] == "job_run"
    assert payload["job"] == "scheduled_update_existing_users"
    assert payload["dry_run"] is True


def test_new_run_id_includes_job_prefix():
    run_id = new_run_id("scheduled_update_existing_users")

    assert run_id.startswith("scheduled-update-existing-users-")
