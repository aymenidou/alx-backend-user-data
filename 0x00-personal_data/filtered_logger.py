#!/usr/bin/env python3
'''0x00-personal_data'''
import logging
from typing import List
import re

PII_FIELDS = ("email", "phone", "ssn", "password")


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


def get_logger() -> logging.Logger:
    '''get logger for user_data'''
    log = logging.getLogger("user_data")
    log.setLevel(logging.INFO)
    log.propagate = False
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(PII_FIELDS))
    log.addHandler(stream_handler)
    return log


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        '''initialisation'''
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        '''format log record and hide sensitive info'''
        message = super(RedactingFormatter, self).format(record)
        exposed_message = filter_datum(
            self.fields, self.REDACTION, message, self.SEPARATOR)
        return exposed_message
