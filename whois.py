import argparse
from ipaddress import IPv4Address
from select import select
from socket import socket, AF_INET, SOCK_STREAM

DEFAULT_WHOIS_PORT = 43
DEFAULT_WOIS_PROVIDER = "whois.ripe.net"

BUFFER_SIZE = 4 * 1024


def get_address(address_string):
    chunks = address_string.split(':')
    return chunks[0], int(chunks[1]) if len(chunks) > 1 else DEFAULT_WHOIS_PORT


def recv_all(sock):
    result = b''
    while select([sock], [], [], 0.25)[0]:
        data = sock.recv(BUFFER_SIZE)
        if len(data) == 0:
            break
        result += data
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Whois tool")
    parser.add_argument("address", help="IP address to resolve")
    parser.add_argument("source", nargs="?", default="%s:%d" % (DEFAULT_WOIS_PROVIDER, DEFAULT_WHOIS_PORT), help="Source server address")
    args = parser.parse_args()
    address = get_address(args.source)
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.connect(address)
        sock.setblocking(0)
        print(recv_all(sock).decode('utf-8'))
        sock.sendall((str(IPv4Address(args.address)) + "\r\n").encode('utf-8'))
        print(recv_all(sock).decode('utf-8'))
