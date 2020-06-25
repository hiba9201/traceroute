#!/usr/bin/env python3

import argparse
import socket
import sys

import logic.traceroute as tr


def create_args():
    parser = argparse.ArgumentParser(
        description='Python3.7 implementation of traceroute utility. ' +
                    'Read "README.md" for more information')
    parser.add_argument('host', type=str,
                        help='Destination to which utility traces route')
    parser.add_argument('-n', '--numerically', action='store_true',
                        dest='is_ip',
                        help='Print addresses only numerically')
    parser.add_argument('-q', '--query', type=int,
                        default=3, dest='packets', action='store',
                        help='Amount of packets per "ttl"')
    parser.add_argument('-w', '--wait', type=int,
                        default=1, dest='wait', action='store',
                        help='Time to wait for a response')
    parser.add_argument('-z', type=int, default=0,
                        dest='pause', action='store',
                        help='Pause time between probes')
    parser.add_argument('-m', '--max', type=int,
                        default=64, dest='hops', action='store',
                        help='Max "ttl"')
    parser.add_argument('-s', '--start', type=int,
                        default=1, dest='start', action='store',
                        help='First time-to-live value')

    return parser.parse_args()


if __name__ == '__main__':
    args = create_args()
    try:
        traceroute = tr.Traceroute(args)
    except PermissionError as e:
        sys.stderr.write(e.strerror + '\n')
        sys.exit(1)
    except socket.gaierror:
        sys.stderr.write('Destination address is unknown\n')
        sys.exit(2)

    result = traceroute.trace()
    print('\n'.join(result))
