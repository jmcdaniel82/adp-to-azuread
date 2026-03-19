import generate_adp_current_vs_scheduled_department_report as report


def _make_employee(employee_id: str, title: str, country_code: str = "US") -> dict:
    return {
        "workerID": {"idValue": employee_id},
        "person": {"legalName": {"givenName": "Jane", "familyName1": "Doe"}},
        "workAssignments": [
            {
                "jobTitle": title,
                "assignedWorkLocations": [
                    {
                        "address": {
                            "countryCode": country_code,
                            "cityName": "Atlanta",
                            "lineOne": "1 Main St",
                            "postalCode": "30301",
                            "countrySubdivisionLevel1": {"codeValue": "GA"},
                        }
                    }
                ],
            }
        ],
        "workerDates": {"hireDate": "2025-03-01"},
    }


def _resolution() -> dict:
    return {
        "proposedDepartmentV2": "Operations",
        "changeAllowed": True,
        "blockReason": "",
        "evidenceUsed": "",
        "confidence": "HIGH",
        "titleInferredDept": "",
        "departmentChangeReferenceField": "",
        "departmentChangeReferenceValue": "",
        "departmentChangePrimaryReason": "",
        "departmentChangeReasonTrace": "",
    }


def _ad_user(employee_id: str, title: str = "Old Title", ad_last_active: str = "") -> dict:
    return {
        "employeeID": employee_id,
        "department": "Operations",
        "manager_dn": "",
        "distinguishedName": "CN=Jane Doe,DC=example,DC=com",
        "displayName": "Jane Doe",
        "title": title,
        "givenName": "Jane",
        "sn": "Doe",
        "company": "",
        "l": "Atlanta",
        "st": "GA",
        "streetAddress": "1 Main St",
        "postalCode": "30301",
        "co": "United States",
        "c": "US",
        "countryCode": 840,
        "userAccountControl": 512,
        "adLastLogonTimestampDateTime": ad_last_active,
        "userPrincipalName": "jane.doe@example.com",
        "mail": "jane.doe@example.com",
        "mailboxYesNoFromAD": "no",
    }


def test_build_rows_marks_title_change_for_existing_ad_user(monkeypatch):
    monkeypatch.setattr(
        report,
        "plan_update_attributes",
        lambda *args, **kwargs: ({}, _resolution(), None, ""),
    )
    monkeypatch.setattr(
        report,
        "diff_update_attributes",
        lambda *args, **kwargs: {"title": [("MODIFY_REPLACE", ["New Title"])]},
    )

    rows = report.build_rows(
        [_make_employee("EMP1", "New Title")],
        object(),
        "DC=example,DC=com",
        {"EMP1": _ad_user("EMP1")},
        {},
        {"employee_id": {}, "mail": {}, "upn": {}},
    )

    assert rows[0]["currentTitle"] == "Old Title"
    assert rows[0]["proposedTitle"] == "New Title"
    assert rows[0]["titleWouldChange"] == "yes"
    assert rows[0]["actionStatus"] == "wouldUpdate"


def test_build_rows_does_not_mark_title_change_when_user_missing_in_ad(monkeypatch):
    monkeypatch.setattr(
        report,
        "plan_update_attributes",
        lambda *args, **kwargs: ({}, _resolution(), None, ""),
    )

    rows = report.build_rows(
        [_make_employee("EMP2", "New Title")],
        object(),
        "DC=example,DC=com",
        {},
        {},
        {"employee_id": {}, "mail": {}, "upn": {}},
    )

    assert rows[0]["currentTitle"] == ""
    assert rows[0]["proposedTitle"] == ""
    assert rows[0]["titleWouldChange"] == "no"
    assert rows[0]["actionStatus"] == "missingInAD"


def test_build_rows_prefers_latest_entra_last_active(monkeypatch):
    monkeypatch.setattr(
        report,
        "plan_update_attributes",
        lambda *args, **kwargs: ({}, _resolution(), None, ""),
    )
    monkeypatch.setattr(report, "diff_update_attributes", lambda *args, **kwargs: {})

    rows = report.build_rows(
        [_make_employee("EMP3", "Analyst")],
        object(),
        "DC=example,DC=com",
        {"EMP3": _ad_user("EMP3", title="Analyst", ad_last_active="2026-03-10T12:00:00Z")},
        {},
        {
            "employee_id": {},
            "mail": {},
            "upn": {},
            "last_active_employee_id": {
                "EMP3": {
                    "dateTime": "2026-03-12T15:30:00Z",
                    "source": "entra:lastSuccessfulSignInDateTime",
                }
            },
            "last_active_mail": {},
            "last_active_upn": {},
        },
    )

    assert rows[0]["entraLastActiveDateTime"] == "2026-03-12T15:30:00Z"
    assert rows[0]["adLastActiveDateTime"] == "2026-03-10T12:00:00Z"
    assert rows[0]["lastActiveDateTime"] == "2026-03-12T15:30:00Z"
    assert rows[0]["lastActiveSource"] == "entra:lastSuccessfulSignInDateTime"


def test_build_rows_falls_back_to_ad_last_active(monkeypatch):
    monkeypatch.setattr(
        report,
        "plan_update_attributes",
        lambda *args, **kwargs: ({}, _resolution(), None, ""),
    )
    monkeypatch.setattr(report, "diff_update_attributes", lambda *args, **kwargs: {})

    rows = report.build_rows(
        [_make_employee("EMP4", "Analyst")],
        object(),
        "DC=example,DC=com",
        {"EMP4": _ad_user("EMP4", title="Analyst", ad_last_active="2026-03-11T09:15:00Z")},
        {},
        {"employee_id": {}, "mail": {}, "upn": {}},
    )

    assert rows[0]["entraLastActiveDateTime"] == ""
    assert rows[0]["adLastActiveDateTime"] == "2026-03-11T09:15:00Z"
    assert rows[0]["lastActiveDateTime"] == "2026-03-11T09:15:00Z"
    assert rows[0]["lastActiveSource"] == "ad:lastLogonTimestamp"
