#!/usr/bin/env python3
'''0x00-personal_data'''
import bcrypt


def hash_password(password: str) -> str:
    '''function that expects one string argument name password and returns
      a salted, hashed password, which is a byte string.'''
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
