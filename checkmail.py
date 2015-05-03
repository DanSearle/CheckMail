#!/usr/bin/env python

"""
    Simple Python module to parse a Thunderbird mail file and
    scan each email message with ClamAV in order to detect
    suspect messages.
"""

import pyclamd
import argparse
import sys
import mailbox


def print_message(parsed, signature=None):
    print "From: {0}, Subject: {1}, Signature: {2}".format(parsed["From"],
                                                           parsed["Subject"],
                                                           signature)

def scan_mail(message):
    result = pyclamd.scan_stream(message.as_string())
    if not result:
        return

    print_message(message, result["stream"])


class HostPortAction(argparse.Action):
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None:
            raise ValueError("nargs not allowed")
        super(HostPortAction, self).__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        values = values.split(":")
        if len(values) == 1:
            values.append(3310)
        else:
            values[1] = int(values[1])
        setattr(namespace, self.dest, tuple(values))

if __name__ == "__main__":
    default_net = ("localhost", 3310)

    parser = argparse.ArgumentParser()
    parser.add_argument('mailfile', nargs='+', type=argparse.FileType('r'),
                        help="mbox mail file to parse, must be a file and not stdin")
    group = parser.add_argument_group('ClamConn')
    group_ex = group.add_mutually_exclusive_group()
    group_ex.add_argument('-s', '--socket', metavar="SOCKET", type=str,
                          default="/var/run/clamav/clamd.ctl",
                          help="Socket file to contact clamd")
    group_ex.add_argument('-n', '--network', metavar="HOST:PORT", type=str, action=HostPortAction,
                          default=default_net,
                          help="Host and port to contact clamd, e.g. localhost:3310")
    args = parser.parse_args()

    if args.network == default_net:
        try:
            pyclamd.init_unix_socket(args.socket)
        except:
            pyclamd.init_network_socket(args.network[0], args.network[1])
    else:
        pyclamd.init_network_socket(args.network[0], args.network[1])

    for filename in args.mailfile:
        for msg in mailbox.mbox(filename.name):
            scan_mail(msg)
