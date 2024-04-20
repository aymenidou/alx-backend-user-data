#!/usr/bin/env python3
'''basic auth module'''
from api.v1.auth.auth import Auth


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
