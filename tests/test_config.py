from app.config import (
    env_truthy,
    get_provision_job_settings,
    get_termed_report_settings,
    get_update_job_settings,
    parse_csv_env,
    parse_int_env,
)


def test_env_truthy_defaults_and_variants(monkeypatch):
    monkeypatch.delenv("FLAG", raising=False)
    assert env_truthy("FLAG", default=True) is True
    monkeypatch.setenv("FLAG", "yes")
    assert env_truthy("FLAG") is True
    monkeypatch.setenv("FLAG", "0")
    assert env_truthy("FLAG") is False


def test_parse_int_env_fallback_and_minimum(monkeypatch):
    monkeypatch.setenv("INT_FIELD", "abc")
    assert parse_int_env("INT_FIELD", 7) == 7
    monkeypatch.setenv("INT_FIELD", "-10")
    assert parse_int_env("INT_FIELD", 7, minimum=1) == 1


def test_parse_csv_env_trims_and_drops_blank_values(monkeypatch):
    monkeypatch.setenv("RECIPIENTS", " one@example.com, , two@example.com ")
    assert parse_csv_env("RECIPIENTS") == ("one@example.com", "two@example.com")


def test_update_job_defaults_and_invalid_lookback(monkeypatch):
    monkeypatch.setenv("UPDATE_DRY_RUN", "true")
    monkeypatch.setenv("UPDATE_LOOKBACK_DAYS", "bad")
    monkeypatch.setenv("UPDATE_INCLUDE_MISSING_LAST_UPDATED", "yes")
    monkeypatch.setenv("UPDATE_LOG_NO_CHANGES", "1")
    settings = get_update_job_settings()
    assert settings.dry_run is True
    assert settings.lookback_days == 7
    assert settings.include_missing_last_updated is True
    assert settings.log_no_changes is True


def test_provision_job_defaults(monkeypatch):
    monkeypatch.delenv("SYNC_HIRE_LOOKBACK_DAYS", raising=False)
    monkeypatch.delenv("PROVISION_MAX_ADD_RETRIES", raising=False)
    monkeypatch.delenv("CN_COLLISION_THRESHOLD", raising=False)
    settings = get_provision_job_settings()
    assert settings.hire_lookback_days == 4
    assert settings.max_add_retries == 15
    assert settings.cn_collision_threshold == 5


def test_termed_report_defaults(monkeypatch):
    monkeypatch.delenv("TERMED_REPORT_LOOKBACK_DAYS", raising=False)
    monkeypatch.delenv("TERMED_REPORT_SMTP_HOST", raising=False)
    monkeypatch.delenv("TERMED_REPORT_SMTP_PORT", raising=False)
    monkeypatch.delenv("TERMED_REPORT_FROM_ADDRESS", raising=False)
    monkeypatch.delenv("TERMED_REPORT_RECIPIENTS", raising=False)
    monkeypatch.delenv("TERMED_REPORT_SUBJECT", raising=False)
    settings = get_termed_report_settings()
    assert settings.lookback_days == 30
    assert settings.smtp_host == "10.209.10.25"
    assert settings.smtp_port == 25
    assert settings.from_address == "90day@cfsbrands.com"
    assert settings.recipients == (
        "jasonmcdaniel@cfsbrands.com",
        "ashleytolbert@cfsbrands.com",
    )
    assert settings.subject == "ADP Last 30 Day Termed Report"
