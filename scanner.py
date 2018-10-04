# use -h flag for usage
# Capabilities:
#   specify host and port   (40 points)
#   allow multiple ports    (10 points)

import getopt
import re
import socket
import sys

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
    try:
        socket.inet_aton(string)
    except socket.error:
        return False
    return True

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
    print("Open TCP Ports:")
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect( (ip, port) )
        except socket.error as e:
            if e.errno == 111:
                continue
            raise
        else:
            print("\t{}".format(port))
            sock.close()

def usage():
    print(usage_string)

if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], "H:hp:", ["help"])
    except getopt.GetoptError as err:
        print(str(err))
        usage()
        sys.exit(1)

    host = "127.0.0.1"
    ports = range(1024)

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit(0)
        elif o == "-H":
            if not is_ip(a):
                print("Invalid IP address: {}".format(a))
                sys.exit(1)
            host = a
        elif o == "-p":
            try:
                ports = port_list(a)
            except ValueError as e:
                print(e.message)
                sys.exit(1)

    scan_host(host, ports)
