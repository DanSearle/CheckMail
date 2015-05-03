#!/usr/bin/env python

"""
    Simple Python module to parse a Thunderbird mail file and
    scan each email message with ClamAV in order to detect
    suspect messages.
"""

import pyclamd
import argparse
import mailbox
import logging

log = logging.getLogger(__name__)
default_net = ("localhost", 3310)


class ScanMessage:
    def __init__(self, key, message):
        self._message = message
        self.key = key
        self.signature = None
        self._scan()

    def _scan(self):
        log.debug("Scanning message {0}".format(self))
        result = pyclamd.scan_stream(self._message.as_string())
        log.debug("Scanned message {0}, result {1}".format(self, result))
        if result:
            self.signature = result["stream"]

    def __repr__(self):
        message = self._message
        return "From: {0}, Subject: {1}, Signature: {2}".format(message["From"],
                                                                message["Subject"],
                                                                self.signature)


def parse_command_line():
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

    parser = argparse.ArgumentParser()
    parser.add_argument('mailfile', nargs='+', type=argparse.FileType('r'),
                        help="mbox mail file to parse, must be a file and not stdin")
    parser.add_argument('-c', '--clean', action="store_true",
                        help="Set to automatically remove messages which have detected viruses")
    parser.add_argument("-v", "--verbose", dest="verbose_count",
                        action="count", default=0,
                        help="increases log verbosity for each occurence.")

    group = parser.add_argument_group('Clamd Connection')
    group_ex = group.add_mutually_exclusive_group()
    group_ex.add_argument('-s', '--socket', metavar="SOCKET", type=str,
                          default="/var/run/clamav/clamd.ctl",
                          help="Socket file to contact clamd")
    group_ex.add_argument('-n', '--network', metavar="HOST:PORT", type=str, action=HostPortAction,
                          default=default_net,
                          help="Host and port to contact clamd, e.g. localhost:3310")
    arguments = parser.parse_args()
    logging.basicConfig(level=max(2 - arguments.verbose_count, 0) * 10)
    return arguments

if __name__ == "__main__":
    args = parse_command_line()

    if args.network == default_net:
        try:
            pyclamd.init_unix_socket(args.socket)
        except:
            pyclamd.init_network_socket(args.network[0], args.network[1])
    else:
        pyclamd.init_network_socket(args.network[0], args.network[1])

    for filename in args.mailfile:
        log.debug("Reading mboxfile {0}".format(filename.name))
        mbox = mailbox.mbox(filename.name)
        log.debug("Loaded mboxfile {0}".format(filename.name))
        try:
            virus_mail = [y for y in [ScanMessage(key, message) for key, message in mbox.iteritems()] if y.signature]
            for v in virus_mail:
                log.info("Found virus in message {0}".format(v))
                if args.clean:
                    log.debug("Locking mailbox {0}".format(filename.name))
                    mbox.lock()
                    try:
                        log.debug("Cleaning {0} from mailbox {1}".format(v, filename.name))
                        log.info("Message {0} removed".format(v.key))
                        mbox.remove(v.key)
                        log.debug("Flushing mailbox {0}".format(filename.name))
                        mbox.flush()
                    finally:
                        log.debug("Unlocking mailbox {0}".format(filename.name))
                        mbox.unlock()
        finally:
            mbox.close()
