import argparse
from ipaddress import IPv4Address
from select import select
from time import time, strftime, gmtime
from socket import socket, AF_INET, SOCK_DGRAM
from struct import pack, unpack
from decimal import Decimal


NTP_PORT = 123
DEFAULT_BUFFER_SIZE = 64 * 1024

NTP_CURRENT_VERSION = 4

NTP_HEADER_FORMAT = ">BBBBII4sQQQQ"
NTP_HEADER_LENGTH = 48
NTP_UTC_OFFSET = 2208988800


def utc_to_ntp_bytes(time):
    return int((Decimal(time) + NTP_UTC_OFFSET) * (2 ** 32))


def ntp_bytes_to_utc(value):
    return Decimal(value) / (2 ** 32) - NTP_UTC_OFFSET


def utc_to_string(value):
    return strftime("%a, %d %b %Y %H:%M:%S UTC", gmtime(value))


def from_ntp_short_bytes(value):
    return Decimal(value) / (2 ** 16)


def hexdump(value, size=4):
    if isinstance(value, bytes):
        return " ".join(["%02X" % e for e in value])
    if isinstance(value, int):
        if size == 1:
            return hexdump(pack('>B', value))
        if size == 2:
            return hexdump(pack('>H', value))
        if size == 4:
            return hexdump(pack('>I', value))
        if size == 8:
            return hexdump(pack('>Q', value))


class Packet(object):
    def __init__(self, leap=0, version=NTP_CURRENT_VERSION, mode=3, stratum=16, poll=0, precision=0, root_delay=0,
                 root_dispersion=0, ref_id=b'', ref_time=0, origin=0, receive=0,
                 transmit=0):
        self.leap = leap
        self.version = version
        self.mode = mode
        self.options = (self.leap << 6) | (self.version << 3) | self.mode
        self.stratum = stratum
        self.poll = poll
        self.precision = precision
        self.root_delay = root_delay
        self.root_dispersion = root_dispersion
        self.ref_id = ref_id
        self.ref_time = ref_time
        self.origin = origin
        self.receive = receive
        self.transmit = transmit

    @classmethod
    def from_binary(cls, data):
        options, stratum, poll, precision, root_delay, root_dispersion, \
        ref_id, ref_time, origin, receive, transmit \
            = unpack(NTP_HEADER_FORMAT, data[:NTP_HEADER_LENGTH])
        leap, version, mode = options >> 6, ((options >> 3) & 0x7), options & 0x7
        return Packet(leap, version, mode, stratum, poll, precision, root_delay, root_dispersion, ref_id, ref_time,
                      origin, receive, transmit)

    @classmethod
    def form_request(cls, version=NTP_CURRENT_VERSION):
        current_time = time()
        return Packet(version=version, transmit=utc_to_ntp_bytes(current_time))

    def to_binary(self):
        return pack(NTP_HEADER_FORMAT,
                    self.options,
                    self.stratum, self.poll, self.precision,
                    self.root_delay,
                    self.root_dispersion,
                    self.ref_id,
                    self.ref_time,
                    self.origin,
                    self.receive,
                    self.transmit)

    def __str__(self):
        return \
            "%-30s Version: %d\n" % (hexdump(self.options, 1), self.version) + \
            "%-30s Leap: %d\n" % ("", self.leap) + \
            "%-30s Mode: %d\n" % ("", self.mode) + \
            "%-30s Stratum: %d\n" % (hexdump(self.stratum, 1), self.stratum) + \
            "%-30s Poll: %lf (%d)\n" % (hexdump(self.poll, 1), 2 ** (-self.poll), self.poll) + \
            "%-30s Precision: %lf (%d)\n" % (hexdump(self.precision, 1), 2 ** (-self.precision), self.precision) + \
            "%-30s Root delay: %lf\n" % (hexdump(self.root_delay, 4), from_ntp_short_bytes(self.root_delay)) + \
            "%-30s Root dispersion: %lf\n" % (hexdump(self.root_dispersion, 4), from_ntp_short_bytes(self.root_dispersion)) + \
            "%-30s Reference ID: %s\n" % (hexdump(self.ref_id), IPv4Address(self.ref_id)) + \
            "%-30s Reference Timestamp: %s\n" % (hexdump(self.ref_time, 8), utc_to_string(ntp_bytes_to_utc(self.ref_time))) + \
            "%-30s Origin Timestamp: %s\n" % (hexdump(self.origin, 8), utc_to_string(ntp_bytes_to_utc(self.origin))) + \
            "%-30s Receive Timestamp: %s\n" % (hexdump(self.receive, 8), utc_to_string(ntp_bytes_to_utc(self.receive))) + \
            "%-30s Transmit Timestamp: %s\n" % (hexdump(self.transmit, 8), utc_to_string(ntp_bytes_to_utc(self.transmit)))


def get_args_parser():
    parser = argparse.ArgumentParser(description="NTP tool")
    parser.add_argument("source", help="Source server address")
    parser.add_argument("-v", "--version", help="NTP version to be used", default=NTP_CURRENT_VERSION, type=int)
    parser.add_argument("-t", "--timeout", help="Communication timeout in seconds (default 1)", default=1, type=int)
    parser.add_argument("-a", "--attempts", help="Maximum communication attempts (default 1)", default=1, type=int)
    parser.add_argument("-f", "--file", help="Use source as filename of NTP packet dump", action='store_true')
    parser.add_argument("-d", "--no-debug", help="Do not show debug info", action='store_false', default=True)
    return parser


def get_address(source):
    chunks = source.split(':')
    return chunks[0], int(chunks[1]) if len(chunks) > 1 else NTP_PORT


def debug(args, message):
    if args.no_debug:
        print(message)


def get_raw_packet(args):
    if args.file:
        with open(args.source, "rb") as file:
            return file.read()
    address = get_address(args.source)
    request = Packet.form_request(version=args.version).to_binary()
    for attempt in range(1, args.attempts + 1):
        with socket(AF_INET, SOCK_DGRAM) as sock:
            sock.sendto(request, address)
            if select([sock], [], [], args.timeout)[0]:
                return sock.recvfrom(DEFAULT_BUFFER_SIZE)[0]
        debug(args, "Attempt %d failed" % attempt)


if __name__ == "__main__":
    parser = get_args_parser()
    args = parser.parse_args()
    raw_packet = get_raw_packet(args)
    if raw_packet:
        print(Packet.from_binary(raw_packet))
    else:
        debug(args, "Failed to receive packet")
