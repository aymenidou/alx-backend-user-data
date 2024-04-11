#!/usr/bin/env python3
'''0x00-personal_data'''
import bcrypt


def hash_password(password: str) -> bytes:
    '''function that expects one string argument name password and returns
      a salted, hashed password, which is a byte string.'''
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    '''function that expects 2 arguments and returns a boolean.
        Arguments:
            hashed_password: bytes type
            password: string type'''
    return bcrypt.checkpw(password.encode(), hashed_password)
