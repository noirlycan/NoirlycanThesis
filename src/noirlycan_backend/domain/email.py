from __future__ import annotations

import re

# Lab/demo accounts use short local domains (admin@lab), not full RFC5322 addresses.
LAB_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+$")


def normalize_lab_email(value: str) -> str:
    email = str(value or "").strip()
    if not LAB_EMAIL_PATTERN.fullmatch(email):
        raise ValueError("Use a simple lab email like analyst@lab")
    return email
