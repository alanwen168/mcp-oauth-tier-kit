"""Stateless PKCE S256 helpers."""

from __future__ import annotations

import base64
import hashlib
import secrets
import string

_UNRESERVED = string.ascii_letters + string.digits + "-._~"
_MIN_LENGTH = 43
_MAX_LENGTH = 128


def is_valid_verifier(verifier: object) -> bool:
    """Return whether *verifier* has RFC 7636 syntax and length."""
    return (
        isinstance(verifier, str)
        and _MIN_LENGTH <= len(verifier) <= _MAX_LENGTH
        and all(character in _UNRESERVED for character in verifier)
    )


def generate_verifier(length: int = 64) -> str:
    """Generate a cryptographically random RFC 7636 code verifier."""
    if isinstance(length, bool) or not isinstance(length, int):
        raise TypeError("length must be an integer")
    if not _MIN_LENGTH <= length <= _MAX_LENGTH:
        raise ValueError("length must be between 43 and 128")
    return "".join(secrets.choice(_UNRESERVED) for _ in range(length))


def s256_challenge(verifier: str) -> str:
    """Create the base64url-without-padding S256 challenge for *verifier*."""
    if not is_valid_verifier(verifier):
        raise ValueError("verifier must be 43-128 RFC 7636 unreserved characters")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
