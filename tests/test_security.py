from pathlib import Path

from app.security import cleanup_temp_files, ensure_file_from_env


def test_ensure_file_from_env_materializes_pem_and_cleans_up(monkeypatch):
    monkeypatch.setenv("TEST_CERT_PEM", "-----BEGIN CERTIFICATE-----\\nABC\\n-----END CERTIFICATE-----")
    path = ensure_file_from_env("TEST_CERT_PEM", ".pem")
    assert path is not None
    assert Path(path).exists()
    cleanup_temp_files()
    assert not Path(path).exists()


def test_ensure_file_from_env_base64_best_effort(monkeypatch):
    # "hello" base64 with whitespace to exercise best-effort decode fallback.
    monkeypatch.setenv("TEST_CERT_B64", " aGVs\\nbG8= ")
    path = ensure_file_from_env("TEST_CERT_B64", ".bin")
    assert path is not None
    with open(path, "rb") as handle:
        assert handle.read() == b"hello"
    cleanup_temp_files()
