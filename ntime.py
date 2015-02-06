import argparse
from socket import socket, AF_INET, SOCK_DGRAM

NTP_PORT = 123
DEFAULT_BUFFER_SIZE = 64 * 1024

def get_args_parser():
    parser = argparse.ArgumentParser(description="NTP tool")
    parser.add_argument("source", help="Source server address")
    return parser


def get_address(source):
    chunks = source.split(':')
    return chunks[0], int(chunks[1]) if len(chunks) > 1 else NTP_PORT


def create_request_packet():
    return b"\x1b" + b"\x00" * 47


def get_packet(args):
    address = get_address(args.source)
    with socket(AF_INET, SOCK_DGRAM) as sock:
        sock.sendto(create_request_packet(), address)
        data, addr = sock.recvfrom(DEFAULT_BUFFER_SIZE)
        return data


if __name__ == "__main__":
    parser = get_args_parser()
    args = parser.parse_args()
    received_packet = get_packet(args)
    print(received_packet)
