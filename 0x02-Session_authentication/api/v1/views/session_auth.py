#!/usr/bin/env python3
"""Routes for Session Authentication."""
from api.v1.views import app_views
from flask import request, jsonify, abort
from models.user import User
import os


@app_views.route("/auth_session/login", methods=["POST"], strict_slashes=False)
def login():
    """Login a user."""
    email = request.form.get("email")
    if email in ["", None]:
        return jsonify({"error": "email missing"}), 400
    password = request.form.get("password")
    if password in ["", None]:
        return jsonify({"error": "password missing"}), 400
    user = User.search({"email": email})
    if user is None or len(user) == 0:
        return jsonify({"error": "no user found for this email"}), 404
    user = user[0]
    if not user.is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401
    from api.v1.app import auth
    sesh_id = auth.create_session(user.id)
    response = jsonify(user.to_json())
    response.set_cookie(os.getenv("SESSION_NAME"), sesh_id)
    return response


@app_views.route("/auth_session/logout", methods=["DELETE"],
                 strict_slashes=False)
def logout():
    """Logout the current user."""
    from api.v1.app import auth
    if auth.destroy_session(request):
        return jsonify({}), 200
    else:
        abort(404)
