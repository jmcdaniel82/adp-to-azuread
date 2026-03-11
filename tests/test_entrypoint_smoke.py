import function_app as root_entrypoint
from app import function_app as package_entrypoint


def test_root_entrypoint_exports_function_app_object():
    assert hasattr(root_entrypoint, "app")
    assert root_entrypoint.app is package_entrypoint.app


def test_package_entrypoint_exposes_expected_handlers():
    assert callable(package_entrypoint.scheduled_provision_new_hires)
    assert callable(package_entrypoint.scheduled_update_existing_users)
    assert callable(package_entrypoint.process_request)
    assert callable(package_entrypoint.export_adp_data)
