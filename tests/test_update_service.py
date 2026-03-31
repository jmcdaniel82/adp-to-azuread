from app.models import UpdateJobSettings
from app.services.update_service import _resolve_effective_enabled_fields


def test_resolve_effective_enabled_fields_defaults_to_manager_scope():
    settings = UpdateJobSettings(
        dry_run=False,
        lookback_days=7,
        include_missing_last_updated=True,
        log_no_changes=False,
    )

    assert _resolve_effective_enabled_fields(settings) == ("manager",)


def test_resolve_effective_enabled_fields_merges_explicit_fields_and_groups():
    settings = UpdateJobSettings(
        dry_run=False,
        lookback_days=7,
        include_missing_last_updated=True,
        log_no_changes=False,
        enabled_fields=("title",),
        enabled_groups=("address",),
    )

    assert _resolve_effective_enabled_fields(settings) == (
        "title",
        "l",
        "postalCode",
        "st",
        "streetAddress",
        "co",
        "c",
        "countryCode",
    )
