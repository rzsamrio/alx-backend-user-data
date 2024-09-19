#!/usr/bin/env python3
"""Session Authentication."""
from api.v1.auth.auth import Auth
from models.user import User
import uuid


class SessionAuth(Auth):
    """Session Auth class."""

    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """Create a new session for a user."""
        if type(user_id) is not str:
            return None
        sesh_id = str(uuid.uuid4())
        self.user_id_by_session_id[sesh_id] = user_id
        return sesh_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """Return the user id linked to a session id."""
        if type(session_id) is not str:
            return None
        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None) -> User:
        """Return the current user based on the session cookie."""
        if request is None:
            return None
        user_id = self.user_id_for_session_id(self.session_cookie(request))
        if user_id is None:
            return None
        return User.get(user_id)

    def destroy_session(self, request=None):
        """Destroy a session."""
        if request is None:
            return False
        sesh_id = self.session_cookie(request)
        if sesh_id is None:
            return False
        if self.user_id_for_session_id(sesh_id) is None:
            return False
        del self.user_id_by_session_id[sesh_id]
        return True
