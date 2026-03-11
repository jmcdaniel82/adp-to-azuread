from app.config import env_truthy, get_provision_job_settings, get_update_job_settings, parse_int_env


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
