#!/usr/bin/env python3
"""Authentication system."""
from typing import List, TypeVar
import os


class Auth:
    """Authentication class."""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Check if a path requires authentication."""
        def like(path: str, pattern: str) -> bool:
            """Check if a path matches a pattern."""
            if pattern[-1] == "*":
                return path.startswith(pattern[:-1])
            return path == pattern

        if path is None or excluded_paths is None or len(path) == 0:
            return True
        new_path = path if path[-1] == "/" else path + "/"
        return not any(
            [like(new_path, pattern) for pattern in excluded_paths]
        )

    def authorization_header(self, request=None) -> str:
        """To be implemented."""
        if request is None:
            return None
        return request.headers.get("Authorization")

    def current_user(self, request=None) -> TypeVar('User'):
        """Return the current user."""
        return None

    def session_cookie(self, request=None):
        """Return the session id."""
        if request is None:
            return None
        cookie_name = os.getenv("SESSION_NAME")
        return request.cookies.get(cookie_name)
