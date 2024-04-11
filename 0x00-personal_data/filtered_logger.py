#!/usr/bin/env python3
'''0x00-personal_data'''
from typing import List
import re


def filter_datum(fields: List[str], redaction: str, message: str,
                 separator: str) -> str:
    '''
    fields: a list of strings representing all fields to obfuscate
    redaction: a string representing by what the field will be obfuscated
    message: a string representing the log line
    separator: a string representing by which character is separating all
      fields in the log line (message)
    '''
    for param_name in fields:
        pattern = re.compile(fr'({param_name}=)[^{separator}]+')
        message = re.sub(pattern, fr'\g<1>{redaction}', message)
    return message
