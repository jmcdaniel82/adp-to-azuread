import json
from types import SimpleNamespace

from app import diagnostics_routes


def make_request(params=None, url="https://example.test/api/diagnostics"):
    return SimpleNamespace(params=params or {}, url=url)


def response_json(response):
    body = response.body
    if isinstance(body, bytes):
        body = body.decode("utf-8")
    return json.loads(body)


def build_worker(
    employee_id,
    given_name,
    family_name,
    *,
    preferred_name=None,
    department="Sales",
    company="CFS",
    hire_date="2026-03-10T00:00:00Z",
    termination_date=None,
    job_title="Associate",
):
    preferred_given = preferred_name or given_name
    return {
        "workerID": {"idValue": employee_id},
        "person": {
            "legalName": {
                "givenName": given_name,
                "familyName1": family_name,
            },
            "preferredName": {
                "givenName": preferred_given,
                "familyName1": family_name,
            },
        },
        "workerDates": {"terminationDate": termination_date} if termination_date else {},
        "customFieldGroup": {
            "stringFields": [
                {
                    "nameCode": {"codeValue": "Business Title"},
                    "stringValue": job_title,
                }
            ]
        },
        "workAssignments": [
            {
                "hireDate": hire_date,
                "jobTitle": job_title,
                "businessUnit": {"name": company},
                "assignedOrganizationalUnits": [
                    {
                        "typeCode": {"codeValue": "Department"},
                        "nameCode": {"shortName": department},
                    }
                ],
            }
        ],
    }


def test_summary_view_returns_expected_counts(monkeypatch):
    workers = [
        build_worker("A1", "Alice", "Smith", department="Sales"),
        build_worker("B2", "Bob", "Jones", department="Operations"),
        build_worker(
            "C3",
            "Cara",
            "Brown",
            department="Finance",
            termination_date="2026-03-11T00:00:00Z",
        ),
    ]
    ldap_map = {"A1": "sales", "X9": "information technology"}

    monkeypatch.setattr(diagnostics_routes, "get_adp_token", lambda: "token")
    monkeypatch.setattr(diagnostics_routes, "get_adp_employees", lambda token: workers)
    monkeypatch.setattr(diagnostics_routes, "fetch_ad_data_task", lambda: ldap_map)

    response = diagnostics_routes.diagnostics_handler(make_request({"view": "summary"}))

    assert response.status_code == 200
    assert response_json(response) == {
        "adpTotal": 3,
        "activeTotal": 2,
        "adpOnlyCount": 2,
        "adOnlyCount": 1,
        "deptPairCount": 1,
    }


def test_department_diff_view_preserves_export_shape(monkeypatch):
    workers = [
        build_worker("A1", "Alice", "Smith", department="Sales"),
        build_worker("B2", "Bob", "Jones", department="Operations"),
    ]
    ldap_map = {"A1": "sales", "B2": "operations", "X9": "finance"}

    monkeypatch.setattr(diagnostics_routes, "get_adp_token", lambda: "token")
    monkeypatch.setattr(diagnostics_routes, "get_adp_employees", lambda token: workers)
    monkeypatch.setattr(diagnostics_routes, "fetch_ad_data_task", lambda: ldap_map)

    response = diagnostics_routes.diagnostics_handler(make_request({"view": "department-diff"}))

    assert response.status_code == 200
    assert response_json(response) == {
        "pairs": [["operations", "operations"], ["sales", "sales"]],
        "adpDepartments": ["operations", "sales"],
        "adDepartments": ["finance", "operations", "sales"],
        "adpOnlyIDs": [],
        "adOnlyIDs": ["X9"],
    }


def test_worker_view_requires_employee_id(monkeypatch):
    monkeypatch.setattr(diagnostics_routes, "get_adp_token", lambda: "token")
    monkeypatch.setattr(diagnostics_routes, "get_adp_employees", lambda token: [])

    response = diagnostics_routes.diagnostics_handler(make_request({"view": "worker"}))

    assert response.status_code == 400
    assert response_json(response) == {"error": "Missing required query parameter: employeeId."}


def test_worker_view_returns_single_targeted_worker(monkeypatch):
    workers = [
        build_worker("A1", "Alice", "Smith", department="Sales"),
        build_worker("B2", "Bob", "Jones", department="Operations"),
    ]

    monkeypatch.setattr(diagnostics_routes, "get_adp_token", lambda: "token")
    monkeypatch.setattr(diagnostics_routes, "get_adp_employees", lambda token: workers)

    response = diagnostics_routes.diagnostics_handler(
        make_request({"view": "worker", "employeeId": " b2 "})
    )

    payload = response_json(response)
    assert response.status_code == 200
    assert payload["employeeId"] == "B2"
    assert payload["status"] == "Active"
    assert payload["department"] == "Operations"
    assert "workAssignments" not in payload


def test_recent_hires_view_limits_and_sorts_results(monkeypatch):
    workers = [
        build_worker("A1", "Alice", "Smith", hire_date="2026-03-01T00:00:00Z"),
        build_worker("B2", "Bob", "Jones", hire_date="2026-03-11T00:00:00Z"),
        build_worker("C3", "Cara", "Brown", hire_date="2026-04-01T00:00:00Z"),
    ]

    monkeypatch.setattr(diagnostics_routes, "get_adp_token", lambda: "token")
    monkeypatch.setattr(diagnostics_routes, "get_adp_employees", lambda token: workers)

    response = diagnostics_routes.diagnostics_handler(
        make_request({"view": "recent-hires", "limit": "1"})
    )

    payload = response_json(response)
    assert response.status_code == 200
    assert payload["limitApplied"] == 1
    assert payload["returned"] == 1
    assert payload["workers"][0]["employeeId"] == "B2"
    assert "workAssignments" not in payload["workers"][0]
