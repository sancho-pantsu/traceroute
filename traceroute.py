import argparse
from tracer import Tracer
import logging

logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)


def read():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--timeout', type=int, default=2)
    parser.add_argument('-p', '--port', type=int, default=None)
    parser.add_argument('-n', '--max-requests-number', type=int, default=None)
    parser.add_argument('-v', '--verbose', action='store_true')

    parser.add_argument('dst', type=str)
    parser.add_argument('protocol', type=str, choices=['tcp', 'udp', 'icmp'])

    arguments = parser.parse_args()
    if arguments.protocol != 'icmp' and arguments.port is None:
        parser.error('For TCP or UDP port is required')
    return arguments


args = read()
print('NUM\tIP\tTIME\t' + ('AS' if args.verbose else ''))
tracer = Tracer(args.dst, args.timeout, args.protocol, args.port, args.max_requests_number, args.verbose)
# tracer = Tracer('1.1.1.1', 5, 'icmp', 53, verbose=True, maxCount=1)
tracer.trace()
