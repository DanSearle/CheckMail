#!/usr/bin/env python

"""
    Simple Python module to parse a Thunderbird mail file and
    scan each email message with ClamAV in order to detect
    suspect messages.
"""

import pyclamav
import os
import re
import email
import argparse
import sys
import tempfile

mail_split_re = re.compile(r'\s(?=From -)')


def print_message(message, signature=None):
    parsed = email.message_from_string(message)
    print "From: {0}, Subject: {1}, Signature: {2}".format(parsed["From"],
                                                           parsed["Subject"],
                                                           signature)


def scan_mail(message):
    temp_message = tempfile.NamedTemporaryFile(delete=False)
    with temp_message as f:
        f.write(message)
    try:
        result = pyclamav.scanfile(temp_message.name)
        if not result[0]:
            return

        print_message(message, result[1])

    finally:
        os.remove(temp_message.name)


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('mailfile', nargs='?', type=argparse.FileType('r'),
                        default=sys.stdin,
                        help="Thunderbird mail file to parse, if not provided input is taken from STDIN")
    args = parser.parse_args()

    for msg in mail_split_re.split(args.mailfile.read()):
        scan_mail(msg)
