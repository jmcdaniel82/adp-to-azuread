from datetime import datetime, timezone

from app import termination_report
from app.models import TermedReportSettings


def _make_employee(
    employee_id: str,
    *,
    termination_date: str | None = None,
    title: str = "Analyst",
    country_code: str = "US",
    last_updated: str | None = None,
) -> dict:
    payload = {
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
                            "countrySubdivisionLevel1": {"codeValue": "GA"},
                        }
                    }
                ],
                "reportsTo": [{"workerID": {"idValue": "MGR1"}}],
            }
        ],
        "workerDates": {"hireDate": "2022-01-15T00:00:00Z"},
    }
    if termination_date:
        payload["workerDates"]["terminationDate"] = termination_date
    if last_updated:
        payload["meta"] = {"lastUpdatedDateTime": last_updated}
    return payload


def _settings(lookback_days: int = 30) -> TermedReportSettings:
    return TermedReportSettings(
        lookback_days=lookback_days,
        smtp_host="10.209.10.25",
        smtp_port=25,
        from_address="90day@cfsbrands.com",
        recipients=("jasonmcdaniel@cfsbrands.com",),
        subject="ADP Last 30 Day Termed Report",
    )


def test_select_recent_terminated_employees_filters_to_last_30_days():
    now = datetime(2026, 3, 16, 12, 0, tzinfo=timezone.utc)
    employees = [
        _make_employee("RECENT1", termination_date="2026-03-10T00:00:00Z"),
        _make_employee("OLD1", termination_date="2026-01-01T00:00:00Z"),
        _make_employee("FUTURE1", termination_date="2026-03-20T00:00:00Z"),
        _make_employee("NOTERM1"),
    ]

    selected, stats = termination_report.select_recent_terminated_employees(
        employees,
        _settings(),
        context="test_recent_terminations",
        now=now,
    )

    assert [employee["workerID"]["idValue"] for employee in selected] == ["RECENT1"]
    assert stats["cutoff_iso"] == "2026-02-14"
    assert stats["missing_termination_date"] == 1
    assert stats["invalid_termination_date"] == 0
    assert stats["outside_window"] == 2


def test_build_termed_report_rows_populates_expected_columns():
    now = datetime(2026, 3, 16, 12, 0, tzinfo=timezone.utc)
    rows = termination_report.build_termed_report_rows(
        [
            _make_employee(
                "RECENT1",
                termination_date="2026-03-10T00:00:00Z",
                last_updated="2026-03-12T08:30:00Z",
            )
        ],
        now=now,
    )

    assert rows == [
        {
            "employeeID": "RECENT1",
            "fullName": "Jane Doe",
            "employeeStatus": "Inactive",
            "terminationDate": "2026-03-10T00:00:00Z",
            "daysSinceTermination": "6",
            "lastUpdatedDateTime": "2026-03-12T08:30:00Z",
            "hireDate": "2022-01-15T00:00:00Z",
            "businessTitle": "Analyst",
            "department": "",
            "company": "",
            "managerEmployeeID": "MGR1",
            "countryCode": "US",
            "city": "Atlanta",
            "state": "GA",
        }
    ]


def test_run_scheduled_last_30_day_termed_report_emails_csv(monkeypatch):
    sent = {}
    now = datetime(2026, 3, 16, 12, 0, tzinfo=timezone.utc)
    settings = _settings()
    employees = [_make_employee("RECENT1", termination_date="2026-03-10T00:00:00Z")]

    monkeypatch.setattr("app.termination_report.get_termed_report_settings", lambda: settings)
    monkeypatch.setattr("app.termination_report.get_adp_token", lambda: "token")
    monkeypatch.setattr("app.termination_report.get_adp_employees", lambda token: employees)
    monkeypatch.setattr(
        "app.termination_report.select_recent_terminated_employees",
        lambda all_employees, current_settings, **kwargs: (
            employees,
            {
                "cutoff_iso": "2026-02-14",
                "deduped_count": 1,
                "missing_termination_date": 0,
                "invalid_termination_date": 0,
                "outside_window": 0,
            },
        ),
    )
    monkeypatch.setattr(
        "app.termination_report.build_termed_report_rows",
        lambda current_employees: [{"employeeID": "RECENT1"}],
    )
    monkeypatch.setattr(
        "app.termination_report.render_termed_report_csv",
        lambda rows: "employeeID\r\nRECENT1\r\n",
    )
    monkeypatch.setattr(
        "app.termination_report.send_termed_report_email",
        lambda current_settings, **kwargs: sent.update(
            {
                "settings": current_settings,
                "report_date": kwargs["report_date"],
                "csv_content": kwargs["csv_content"],
                "row_count": kwargs["row_count"],
            }
        ),
    )

    class _FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return now if tz else now.replace(tzinfo=None)

    monkeypatch.setattr("app.termination_report.datetime", _FrozenDateTime)

    termination_report.run_scheduled_last_30_day_termed_report(None)

    assert sent["settings"] == settings
    assert sent["report_date"] == now
    assert sent["csv_content"] == "employeeID\r\nRECENT1\r\n"
    assert sent["row_count"] == 1
