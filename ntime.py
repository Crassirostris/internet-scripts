#!/usr/bin/python3

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

LEAP_STRING_VALUE = ["No warning",
               "Last minute of the day has 61 seconds",
               "Last minute of the day has 59 seconds",
               "Unknown (clock unsynchronized)"]

MODE_STRING_VALUE = ["Reserved",
               "Symmetric active",
               "Symmetric passive",
               "Client",
               "Server",
               "Broadcast",
               "NTP control message",
               "Reserved for private use"]


def utc_to_ntp_bytes(time):
    return int((Decimal(time) + NTP_UTC_OFFSET) * (2 ** 32))


def ntp_bytes_to_utc(value):
    return Decimal(value) / (2 ** 32) - NTP_UTC_OFFSET


def utc_to_string(value):
    return strftime("%a, %d %b %Y %H:%M:%S UTC", gmtime(value))


def from_ntp_short_bytes(value):
    return Decimal(value) / (2 ** 16)


def from_ntp_time_bytes(value):
    return Decimal(value) / (2 ** 32)


def get_bytes(value, size=None):
    if isinstance(value, bytes):
        return " ".join(["%02X" % e for e in value])
    if isinstance(value, int):
        if size == 1:
            return get_bytes(pack('>B', value))
        if size == 2:
            return get_bytes(pack('>H', value))
        if size == 4:
            return get_bytes(pack('>I', value))
        if size == 8:
            return get_bytes(pack('>Q', value))


def get_bits(size, bits_count, bits_offset, value):
    bytes = pack('>I', value)
    binary_string = ''.join(['{0:08b}'.format(byte) for byte in bytes])
    return '.' * bits_offset + binary_string[-bits_count:] + '.' * (size * 8 - bits_count - bits_offset)


def hexdump(series):
    offset = 0
    result = ''
    for row in series:
        if len(row) == 4:
            size, title, binary_value, value = row
            result += '%04X: %-30s %s: %s\n' % (offset, get_bytes(binary_value, size), title, str(value))
            offset += size
        else:
            size, pieces = row
            local_result = ''
            bits_offset = 0
            for piece in pieces:
                bits_count, title, binary_value, value = piece
                local_result += '      %-30s %s: %s\n' \
                                % (get_bits(size, bits_count, bits_offset, binary_value), title, str(value))
                bits_offset += bits_count
            result += ('%04X:' % offset) + local_result[5:]
            offset += size
    return result


class Packet(object):
    def __init__(self, leap=0, version=NTP_CURRENT_VERSION, mode=3, stratum=16, poll=0, precision=0, root_delay=0,
                 root_dispersion=0, ref_id=b'\x00' * 4, ref_time=0, origin=0, receive=0,
                 transmit=0):
        self.leap = leap
        self.version = version
        self.mode = mode
        self.options = (self.leap << 6) | (self.version << 3) | self.mode
        self.stratum = stratum
        self.poll_binary = poll
        self.poll = 2 ** (-poll)
        self.precision_binary = precision
        self.precision = 2 ** (-precision)
        self.root_delay_binary = root_delay
        self.root_delay = from_ntp_short_bytes(root_delay)
        self.root_dispersion_binary = root_dispersion
        self.root_dispersion = from_ntp_short_bytes(root_dispersion)
        self.ref_id_binary = ref_id
        self.ref_id = str(IPv4Address(ref_id))
        self.ref_time_binary = ref_time
        self.ref_time = from_ntp_time_bytes(ref_time)
        self.origin_binary = origin
        self.origin = from_ntp_time_bytes(origin)
        self.receive_binary = receive
        self.receive = from_ntp_time_bytes(receive)
        self.transmit_binary = transmit
        self.transmit = from_ntp_time_bytes(transmit)

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
                    self.stratum,
                    self.poll_binary,
                    self.precision_binary,
                    self.root_delay_binary,
                    self.root_dispersion_binary,
                    self.ref_id_binary,
                    self.ref_time_binary,
                    self.origin_binary,
                    self.receive_binary,
                    self.transmit_binary)


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
        packet = Packet.from_binary(raw_packet)
        print(hexdump((
            (1,
                ((2, 'Leap', packet.leap, LEAP_STRING_VALUE[packet.leap]),
                 (3, 'Version', packet.version, packet.version),
                 (3, 'Mode', packet.mode, MODE_STRING_VALUE[packet.mode]))),
            (1, 'Stratum', packet.stratum, packet.stratum),
            (1, 'Poll', packet.poll_binary, packet.poll),
            (1, 'Precision', packet.precision_binary, packet.precision),
            (4, 'Root delay', packet.root_delay_binary, packet.root_delay),
            (4, 'Root dispersion', packet.root_dispersion_binary, packet.root_dispersion),
            (4, 'Reference ID', packet.ref_id_binary, packet.ref_id),
            (8, 'Reference timestamp', packet.ref_time_binary, packet.ref_time),
            (8, 'Origin timestamp', packet.origin_binary, packet.origin),
            (8, 'Receive timestamp', packet.receive_binary, packet.receive),
            (8, 'Transmit timestamp', packet.transmit_binary, packet.transmit)
        )))
    else:
        debug(args, "Failed to receive packet")
