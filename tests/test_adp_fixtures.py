import json
from pathlib import Path

from app.adp import (
    dedupe_workers_by_employee_id,
    extract_business_title,
    extract_company,
    extract_department,
    extract_employee_id,
    extract_last_updated,
    extract_manager_id,
    extract_state_from_work,
    extract_work_address_field,
    get_display_name,
    get_hire_date,
    get_status,
    get_termination_date,
)
from app.department_resolution import normalize_department_name, resolve_local_ac_department

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "adp"


def _load_fixture(name: str):
    return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))


def test_complete_worker_fixture_matches_expected_extractors():
    worker = _load_fixture("active_worker_complete.json")

    assert extract_employee_id(worker) == "EMP-FULL-001"
    assert get_display_name(worker["person"]) == "Ada Lovelace"
    assert extract_business_title(worker) == "Senior Analyst"
    assert extract_company(worker) == "CFS Brands"
    assert extract_department(worker) == "Finance"
    assert extract_manager_id(worker) == "MGR-001"
    assert extract_work_address_field(worker, "cityName") == "Atlanta"
    assert extract_state_from_work(worker) == "GA"
    assert get_hire_date(worker) == "2026-02-01T00:00:00+00:00"
    assert get_status(worker) == "Active"
    assert extract_last_updated(worker) is not None


def test_partial_worker_fixture_returns_safe_empty_values():
    worker = _load_fixture("partial_worker_missing_fields.json")

    assert extract_employee_id(worker) == "EMP-PARTIAL-001"
    assert extract_business_title(worker) is None
    assert extract_company(worker) == ""
    assert extract_department(worker) == ""
    assert extract_manager_id(worker) is None
    assert extract_work_address_field(worker, "cityName") == ""
    assert extract_state_from_work(worker) == ""
    assert get_hire_date(worker) is None
    assert get_termination_date(worker) is None


def test_malformed_worker_fixture_does_not_crash_date_extractors():
    worker = _load_fixture("malformed_worker_dates.json")

    assert extract_employee_id(worker) == "EMP-MALFORMED-001"
    assert extract_last_updated(worker) is None
    assert get_hire_date(worker) is None
    assert get_termination_date(worker) == "bad-term-date"


def test_duplicate_worker_fixture_prefers_latest_last_updated_record():
    workers = _load_fixture("duplicate_workers.json")

    deduped = dedupe_workers_by_employee_id(workers, context="fixture_duplicate_test")

    assert len(deduped) == 1
    assert extract_employee_id(deduped[0]) == "EMP-DUP-001"
    assert extract_business_title(deduped[0]) == "New Title"


def test_customer_service_override_fixture_maps_to_sales():
    worker = _load_fixture("customer_service_override_worker.json")

    result = resolve_local_ac_department(worker)

    assert normalize_department_name(result["proposedDepartmentV2"]) == "Sales"
