#!/usr/bin/env python3
"""auth module"""
import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self) -> None:
        """initialize"""
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """register user"""
        try:
            user = self._db.find_user_by(email=email)
            if (user):
                raise ValueError('User {} already exists'.format(email))
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))


def _hash_password(password: str) -> bytes:
    """hash the password"""
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return hashed
