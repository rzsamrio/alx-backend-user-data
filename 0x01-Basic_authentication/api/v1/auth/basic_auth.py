#!/usr/bin/env python3
"""Basic authentication."""
from api.v1.auth.auth import Auth
import base64
import binascii
from typing import TypeVar
from models.user import User


class BasicAuth(Auth):
    """Basic authentication class."""

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """Extract base64 string from Authorization header."""
        if type(authorization_header) is not str:
            return None
        elif authorization_header[:6] == "Basic ":
            return authorization_header[6:]
        else:
            return None

    def decode_base64_authorization_header(
            self,
            base64_authorization_header: str
    ) -> str:
        """Decode a base64 string."""
        if type(base64_authorization_header) is not str:
            return None
        try:
            return base64.b64decode(base64_authorization_header,
                                    validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            return None

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: str
    ) -> (str, str):
        """Extract user credentials from decoded header."""
        if type(decoded_base64_authorization_header) is not str:
            return None, None
        split = decoded_base64_authorization_header.split(":")
        if len(split) < 2:
            return None, None
        else:
            return split[0], ":".join(split[1:])

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """Get user object from credentials."""
        if [type(user_email), type(user_pwd)] != [str, str]:
            return None
        users = User.search({"email": user_email})
        if len(users) == 0:
            return None
        if users[0].is_valid_password(user_pwd):
            return users[0]
        else:
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Get the current user."""
        auth_key = self.extract_base64_authorization_header(
            self.authorization_header(request)
        )
        auth_key = self.decode_base64_authorization_header(auth_key)
        email, pwd = self.extract_user_credentials(auth_key)
        return self.user_object_from_credentials(email, pwd)
