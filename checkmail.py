#!/usr/bin/env python

"""
    Simple Python module to parse a Thunderbird mail file and
    scan each email message with ClamAV in order to detect
    suspect messages.
"""

import pyclamav
import os
import email
import argparse
import sys
import tempfile
import mailbox


def print_message(parsed, signature=None):
    print "From: {0}, Subject: {1}, Signature: {2}".format(parsed["From"],
                                                           parsed["Subject"],
                                                           signature)


def scan_mail(message):
    temp_message = tempfile.NamedTemporaryFile(delete=False)
    with temp_message as f:
        f.write(message.as_string())
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
                        help="mbox mail file to parse, if not provided input is taken from STDIN")
    args = parser.parse_args()
    mbox = mailbox.mbox(args.mailfile.name)

    for msg in mbox:
        scan_mail(msg)
