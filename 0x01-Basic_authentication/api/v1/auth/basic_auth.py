#!/usr/bin/env python3
'''basic auth module'''
from api.v1.auth.auth import Auth
from typing import TypeVar


class BasicAuth(Auth):
    '''this is for basic auth'''

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        '''returns the Base64 part of the Authorization header for a Basic
          Authentication'''
        if (authorization_header is None or
                type(authorization_header) != str or
                not authorization_header.startswith('Basic ')):
            return None
        import re
        return re.sub('^Basic ', '', authorization_header)

    def decode_base64_authorization_header(
            self,
            base64_authorization_header: str) -> str:
        ''' returns the decoded value of a Base64 string
            base64_authorization_header'''
        if (base64_authorization_header is None or
                type(base64_authorization_header) != str):
            return None
        import base64
        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            decoded_string = decoded_bytes.decode()
            return decoded_string
        except Exception:
            return None

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: str) -> (str, str):
        ''' returns the user email and password from
          the Base64 decoded value.'''
        if (decoded_base64_authorization_header is None
                or not isinstance(decoded_base64_authorization_header, str)):
            return None, None

        if ':' not in decoded_base64_authorization_header:
            return None, None

        user_email, user_password = decoded_base64_authorization_header.split(
            ':', 1)
        return user_email, user_password

    def user_object_from_credentials(self,
                                     user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        '''returns the User instance based on his email and password.'''
        from models.user import User
        if not isinstance(user_email, str) or user_email is None:
            return None
        if not isinstance(user_pwd, str) or user_pwd is None:
            return None

        # Lookup user by email
        user = User()
        user.email = user_email
        user.password = user_pwd
        print(user.__dict__)
        new_user = User.search(user.__dict__)

        # if new_user is None:
        #     return None

        # Check if password matches
        # if not user.is_valid_password(user_pwd):
        #     return None

        return new_user
