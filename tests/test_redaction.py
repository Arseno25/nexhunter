"""Secret redaction tests."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.security.redaction import SecretRedactor


def test_redact_aws_key():
    """Test AWS access key ID is redacted."""
    print("[TEST] Redact AWS access key...")
    redactor = SecretRedactor()
    out = redactor.redact_string("key is AKIAIOSFODNN7EXAMPLE here")
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "[REDACTED]" in out
    print("  [OK] AWS key redacted")


def test_redact_github_token():
    """Test GitHub personal access token is redacted."""
    print("[TEST] Redact GitHub token...")
    redactor = SecretRedactor()
    token = "ghp_" + "a" * 36
    out = redactor.redact_string(f"token={token}")
    assert token not in out
    print("  [OK] GitHub token redacted")


def test_redact_password_assignment():
    """Test password value is redacted."""
    print("[TEST] Redact password assignment...")
    redactor = SecretRedactor()
    out = redactor.redact_string("password: hunter2secret")
    assert "hunter2secret" not in out
    print("  [OK] Password redacted")


def test_redact_plain_database_url():
    """Test plain (non-SQLAlchemy) database URL credentials are redacted."""
    print("[TEST] Redact database connection strings...")
    redactor = SecretRedactor()
    for url in [
        "postgres://admin:s3cr3tpw@db.internal:5432/app",
        "postgresql+psycopg2://admin:s3cr3tpw@db.internal/app",
        "mongodb://root:s3cr3tpw@mongo:27017",
    ]:
        out = redactor.redact_string(url)
        assert "s3cr3tpw" not in out, f"credentials leaked in {url}"
    print("  [OK] Database credentials redacted")


def test_redact_jwt():
    """Test JWT token is redacted."""
    print("[TEST] Redact JWT...")
    redactor = SecretRedactor()
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.abcDEF123"
    out = redactor.redact_string(f"Authorization header {jwt}")
    assert jwt not in out
    print("  [OK] JWT redacted")


def test_redact_nested_dict():
    """Test nested dict values are redacted recursively."""
    print("[TEST] Redact nested structures...")
    redactor = SecretRedactor()
    data = {
        "host": "10.0.0.5",
        "creds": {"password": "supersecret123", "notes": ["AKIAIOSFODNN7EXAMPLE"]},
    }
    out = redactor.redact_dict(data)
    assert out["host"] == "10.0.0.5"
    assert "supersecret123" not in str(out)
    assert "AKIAIOSFODNN7EXAMPLE" not in str(out)
    print("  [OK] Nested secrets redacted")


def test_redact_command_flag_values():
    """Test secret values following known flags are redacted."""
    print("[TEST] Redact command arguments...")
    redactor = SecretRedactor()
    out = redactor.redact_command(["hydra", "-l", "admin", "-p", "letmein", "10.0.0.5"])
    assert "letmein" not in out
    assert "hydra" in out
    assert "10.0.0.5" in out
    print("  [OK] Command secrets redacted")


def test_redact_command_inline_value():
    """Test --key=value form is redacted."""
    print("[TEST] Redact inline flag values...")
    redactor = SecretRedactor()
    out = redactor.redact_command(["tool", "--api-key=abcd1234efgh5678ijkl"])
    assert "abcd1234efgh5678ijkl" not in out
    print("  [OK] Inline secret redacted")


def test_clean_output_unchanged():
    """Test benign scan output is not mangled."""
    print("[TEST] Preserve benign output...")
    redactor = SecretRedactor()
    text = "Nmap scan report for 192.168.1.10\n22/tcp open ssh OpenSSH 8.9"
    assert redactor.redact_string(text) == text
    print("  [OK] Benign output preserved")


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("\nAll redaction tests passed")
