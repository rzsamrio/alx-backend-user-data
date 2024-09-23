#!/usr/bin/env python3
"""Integration tests."""
import requests


def url(route):
    """Return the url for a route."""
    return "http://0.0.0.0:5000/{}".format(route)


def register_user(email: str, password: str) -> None:
    """Register a user."""
    resp = requests.post(url("users"),
                         data={"email": email, "password": password})
    assert resp.status_code == 200
    assert resp.json() == {"email": email, "message": "user created"}


def log_in_wrong_password(email: str, password: str) -> None:
    """Log in with wrong password."""
    resp = requests.post(url("sessions"),
                         data={"email": email, "password": password})
    assert resp.status_code == 401


def log_in(email: str, password: str) -> str:
    """Log in with the correct password."""
    resp = requests.post(url("sessions"),
                         data={"email": email, "password": password})
    assert resp.status_code == 200
    assert resp.cookies.get("session_id") is not None
    assert resp.json() == {"email": email, "message": "logged in"}
    return resp.cookies.get("session_id")


def profile_unlogged() -> None:
    """Test accessing the user profile without logging in."""
    resp = requests.get(url("profile"))
    assert resp.status_code == 403


def profile_logged(session_id: str) -> None:
    """Test accessing a logged in user's profile."""
    resp = requests.get(url("profile"), cookies={"session_id": session_id})
    assert resp.status_code == 200


def log_out(session_id: str) -> None:
    """Test logging out."""
    resp = requests.delete(url("sessions"),
                           cookies={"session_id": session_id})
    assert resp.status_code == 200
    resp = requests.get(url("profile"), cookies={"session_id": session_id})
    assert resp.status_code == 403


def reset_password_token(email: str) -> str:
    """Get a password reset token."""
    resp = requests.post(url("reset_password"), data={"email": email})
    assert resp.status_code == 200
    json_resp = resp.json()
    assert "reset_token" in json_resp
    assert json_resp["email"] == email
    return json_resp["reset_token"]


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """Test updating a user's password."""
    resp = requests.put(url("reset_password"),
                        data={"email": email, "reset_token": reset_token,
                              "new_password": new_password})
    assert resp.status_code == 200
    assert resp.json() == {"email": email, "message": "Password updated"}


EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"


if __name__ == "__main__":

    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
