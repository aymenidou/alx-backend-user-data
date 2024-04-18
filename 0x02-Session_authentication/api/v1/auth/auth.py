#!/usr/bin/env python3
'''authentification module'''


class Auth():
    '''Auth class'''
    from flask import request
    from typing import List, TypeVar

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        '''require auth'''
        import re
        if path is None or excluded_paths is None or not excluded_paths:
            return True
        path_noslash = re.sub('/$', '', path)
        path_slash = path_noslash+'/'
        if path_noslash in excluded_paths or path_slash in excluded_paths:
            return False
        elif not (path_noslash in excluded_paths
                  or path_slash in excluded_paths):
            return True
        return False

    def authorization_header(self, request=None) -> str:
        '''authorization header'''
        if (request is None):
            return None
        return re

    def current_user(self, request=None) -> TypeVar('User'):
        '''current user'''
        return None
