#!/usr/bin/env python3
from auth import Auth
from flask import Flask, redirect, jsonify, request, abort, make_response
app = Flask(__name__)


AUTH = Auth()


@app.route("/", methods=['GET'])
def index():
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'])
def register_user():
    """register user"""
    email = request.form.get('email')
    password = request.form.get('password')

    try:
        AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"})
    except ValueError as e:
        return jsonify({"message": "email already registered"}), 400


@app.route("/sessions", methods=['POST'])
def login():
    """login and save session id"""
    email = request.form.get('email')
    password = request.form.get('password')
    if AUTH.valid_login(email=email, password=password):
        session_id = AUTH.create_session(email=email)
        response = make_response(
            jsonify({"email": email, "message": "logged in"}))
        response.set_cookie('session_id', session_id)
        return response
    else:
        abort(401)


@app.route("/sessions", methods=['DELETE'])
def logout():
    """delete user session"""
    session_id = request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(session_id)
    if (user is None):
        abort(403)

    AUTH.destroy_session(user.id)
    return redirect('/')


@app.route("/profile", methods=['GET'])
def profile():
    """fetch user email"""
    session_id = request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(session_id)
    if (user):
        return jsonify({"email": user.email})
    else:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
