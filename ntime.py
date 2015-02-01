import argparse
import socket
import sys

NTP_DEFAULT_PORT = 123

RECEIVE_BUFFER_SIZE_BYTES = 64 * 1024

class Packet:
    def __init__(self):
        raise NotImplementedError()

    @classmethod
    def form_request(cls):
        raise NotImplementedError()

    @classmethod
    def from_binary(cls, binary):
        raise NotImplementedError()


def create_args_parser():
    parser = argparse.ArgumentParser(description="NTP tool")
    source_group = parser.add_argument_group("Source", "Either file source of network source should be specified")
    source_group.add_argument("-f", "--file", help="Source file")
    source_group.add_argument("-s", "--server", help="SNTP server to be requested in format server[:port]")
    options_group = parser.add_argument_group("Options")
    options_group.add_argument("-t", "--timeout", help="Socket timeout for network communications")
    options_group.add_argument("-a", "--attempts", help="Attempts count for network communications")
    return parser


def get_raw_packet_from_file(args):
    try:
        with open(args.file, 'rb') as file_stream:
            return file_stream.read()
    except Exception as e:
        sys.stderr.write("Error during reading file:\n%s\n" % str(e))
        return None


def get_raw_packet_from_server(args):
    address_chunks = args.server.split(':')
    address = (address_chunks[0], int(address_chunks[1]) if len(address_chunks) > 1 else NTP_DEFAULT_PORT)
    for attempt in range(1, args.attempts):
        if attempt > 1:
            sys.stderr.wirte("Attempt %d failed, trying again" % (attempt - 1))
        try:
            with socket.socket((socket.AF_INET, socket.SOCK_STREAM)) as sock:
                sock.settimeout(args.timeout)
                sock.connect(address)
                sock.sendall(Packet.form_request().to_binary())
                data = []
                buffer = sock.recv(RECEIVE_BUFFER_SIZE_BYTES)
                while len(buffer) > 0:
                    data.append(buffer)
                    buffer = sock.recv(RECEIVE_BUFFER_SIZE_BYTES)
                return data
        except Exception as e:
            sys.stderr.write("Error during receiving packet:\n%s\n" % str(e))
    return None


def get_packet(args):
    if args.file is None and args.server is None:
        sys.stderr.write('Neither file nor server provided\n')
        return None
    data = None
    if args.file is not None:
        data = get_raw_packet_from_file(args)
    if args.file is not None:
        data = get_raw_packet_from_server(args)
    return Packet.from_binary(data)


if __name__ == "__main__":
    args_parser = create_args_parser()
    args = args_parser.parse_args()
    packet = get_packet(args)
    if packet is None:
        sys.stderr.write('Failed to retrieve packet. Aborting...\n')
        exit(1)
    if args.hexdump:
        print(packet.hexdump())
    elif args.verbose:
        print(packet.verbose())
    else:
        print(packet)