# use -h flag for usage
# Capabilities:
#   specify host and port   (40 points)
#   allow multiple ports    (10 points)

import getopt
import re
import socket
import struct
import sys

cidr_regex = re.compile(r'^((?:(?:[1-9]?\d|1\d{2}|2(?:[0-4]\d|5[0-5]))\.){3}(?:[1-9]?\d|1\d{2}|2(?:[0-4]\d|5[0-5])))(?:/([12]?\d|3[0-2]))?$')
range_regex = re.compile(r'^(\d+)-(\d+)$')

usage_string = """\
Usage: python {} [OPTION]...

OPTIONS
\t-h
\t\tprint this help message and exit
\t-H=HOST
\t\tHOST must be a single IPv4 address
\t-p=PORTS
\t\tPORTS is a comma separated list of either single port numbers or ranges of ports
\t\t\tFor example: 1,3,7,18-22,53,80-500""".format(sys.argv[0])

def is_ip(string):
    return bool(re.match(cidr_regex, string))

def int_to_ip(num):
    return socket.inet_ntoa(struct.pack("!I", num))

def ip_to_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def host_list(string):
    segments = string.split(",")
    hosts = set()

    for segment in segments:
        match = re.match(cidr_regex, segment)
        if match:
            host = match.group(1)
            if match.group(2):
                masklen = int(match.group(2))
                mask = ((1 << masklen) - 1) << (32 - masklen)

                network = ip_to_int(host) & mask
                for addr in xrange(network, network + (1 << (32 - masklen))):
                    hosts.add(int_to_ip(addr))
            else:
                hosts.add(host)
        else:
            try:
                start, end = segment.split("-")
            except ValueError:
                raise ValueError("Invalid IP range: '{}'".format(segment))

            try:
                start = ip_to_int(start)
            except socket.error:
                raise ValueError("Invalid IP: '{}'".format(start))

            try:
                end = ip_to_int(end)
            except socket.error:
                raise ValueError("Invalid IP: '{}'".format(end))

            if start >= end:
                raise ValueError("Invalid IP range: '{}'".format(segment))

            for addr in xrange(start, end+1):
                hosts.add(int_to_ip(addr))

    return sorted(hosts, key=socket.inet_aton)

def port_list(string):
    segments = string.split(",")
    ports = set()
    for segment in segments:
        if segment.isdigit():
            ports.add(int(segment))
        elif re.match(range_regex, segment):
            start, end = (int(num) for num in segment.split("-"))
            if start >= end:
                raise ValueError("Invalid range: {}".format(segment))
            ports = ports.union(range(start, end+1))
    ports = sorted(ports)
    if ports[0] < 0:
        raise ValueError("Invalid port number: {}".format(ports[0]))
    elif ports[-1] > 0xffff:
        raise ValueError("Invalid port number: {}".format(ports[-1]))

    return ports

# ip = IPv4 address
# ports = iterable of integers
def scan_host(ip, ports):
    print("Host: {}".format(ip))
    printed = False
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        try:
            sock.connect( (ip, port) )
        except socket.error as e:
            if e.errno == 111:
                continue
            else:
                print(str(e))
                break
            raise
        else:
            if not printed:
                print("Open TCP Ports:")
                printed = True

            print("\t{}".format(port))
            sock.close()
    print("")

def usage():
    print(usage_string)

if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], "H:hp:", ["help"])
    except getopt.GetoptError as err:
        print(str(err))
        usage()
        sys.exit(1)

    hosts = ["127.0.0.1"]
    ports = range(1024)

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit(0)
        elif o == "-H":
            hosts = host_list(a)
        elif o == "-p":
            try:
                ports = port_list(a)
            except ValueError as e:
                print(e.message)
                sys.exit(1)

    for host in hosts:
        scan_host(host, ports)
