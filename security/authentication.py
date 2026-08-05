"""Bearer token authentication with constant-time comparison."""

import hmac
import hashlib
import os
from typing import Optional, Tuple


class AuthenticationError(Exception):
    """Authentication failed."""
    pass


class TokenValidator:
    """Validate bearer tokens using constant-time comparison."""

    def __init__(self, token: Optional[str] = None):
        """Initialize with configured token (from env or param)."""
        self.token = token or os.environ.get("NEXHUNTER_API_TOKEN", "")
        self.token_hash = self._hash_token(self.token) if self.token else None
        self.enabled = bool(self.token)

    @staticmethod
    def _hash_token(token: str) -> str:
        """Hash token for storage."""
        return hashlib.sha256(token.encode()).hexdigest()

    def validate(self, auth_header: Optional[str]) -> Tuple[bool, Optional[str]]:
        """
        Validate authorization header.

        Returns: (is_valid, error_message)
        - (True, None) - valid token
        - (False, error_msg) - invalid or missing
        """
        if not self.enabled:
            # No token configured - allow (development mode)
            return True, None

        if not auth_header:
            return False, "Missing Authorization header"

        if not auth_header.startswith("Bearer "):
            return False, "Invalid Authorization header format"

        provided_token = auth_header[7:]  # Remove "Bearer " prefix

        # Constant-time comparison prevents timing attacks
        provided_hash = self._hash_token(provided_token)
        is_valid = hmac.compare_digest(provided_hash, self.token_hash)

        if not is_valid:
            return False, "Invalid token"

        return True, None

    def validate_or_raise(self, auth_header: Optional[str]) -> None:
        """Validate token, raise AuthenticationError if invalid."""
        is_valid, error = self.validate(auth_header)
        if not is_valid:
            raise AuthenticationError(error or "Authentication failed")
