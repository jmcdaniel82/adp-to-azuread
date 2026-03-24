"""Password generation helpers for provisioning flows."""

from __future__ import annotations

import re
import secrets
import string


def generate_password(length: int = 24) -> str:
    """Generate a random complex password suitable for AD create flow."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            re.search(r"[a-z]", password)
            and re.search(r"[A-Z]", password)
            and re.search(r"\d", password)
            and re.search(r"[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]", password)
        ):
            return password
