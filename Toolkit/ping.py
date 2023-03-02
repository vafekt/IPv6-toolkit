#!/usr/bin/python3
import argparse
import sys
import netifaces as ni
import netifaces
import psutil
from scapy.arch import get_if_hwaddr
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6, fragment6
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sendpfast
from scapy.volatile import RandString, RandShort
from validate_parameters import is_valid_ipv6, validate_file, is_valid_port
from validate_parameters import is_valid_mac
from validate_parameters import is_valid_num
from validate_parameters import payload


def main():
    parser = argparse.ArgumentParser(description="Sending PING (ICMPv6 Echo Request) message from a given source IPv6 "
                                                 "address to a given destination IPv6 address with specified number "
                                                 "of packets, size of data and option to flood.")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender")
    parser.add_argument("-smac", dest="source_mac", action="store",
                        help="the MAC address of sender (resolved from the interface if skipping)")
    parser.add_argument("-sip", dest="source_ip", action="store", help="the IPv6 address of sender (resolved from the"
                                                                       " interface if skipping)")
    parser.add_argument("-dip", dest="destination_ip", action="store", help="the IPv6 address of destination (ff02::1"
                                                                            " if skipping)")
    parser.add_argument("-n", dest="num_packets", action="store", default=1, type=int,
                        help="the number of packets to send (set to 1 when skipping)")
    parser.add_argument("-l", dest="data_length", type=int, action="store",
                        help="the size of data in bytes")
    parser.add_argument("-i", dest="filename", action="store", type=validate_file,
                        help="input file to send", metavar="FILE")
    parser.add_argument("-f", dest="flood", action="store_true", help="flood the target")
    args = parser.parse_args()

    # Validate the input
    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)

    # Validate the network interface
    if not args.interface:
        print("---> Network interface is required!!!")
        parser.print_help()
        sys.exit(1)
    interface_list = netifaces.interfaces()
    while True:
        if args.interface in interface_list:
            break
        else:
            print("---> The given interface is invalid. Try again!!!")
            sys.exit(1)

    # Validate the source IPv6 address
    if args.source_ip is None:
        args.source_ip = ni.ifaddresses(args.interface)[ni.AF_INET6][0]['addr']
        args.source_ip = args.source_ip.replace("%", '')
        args.source_ip = args.source_ip.replace(args.interface, '')
    if args.source_ip is not None:
        if not is_valid_ipv6(args.source_ip):
            print("---> The given source IPv6 address is invalid. Try again!!!")
            sys.exit(1)

    # Validate the destination IPv6 address
    if args.destination_ip is None:
        args.destination_ip = "ff02::1"
    if args.destination_ip is not None:
        if not is_valid_ipv6(args.destination_ip):
            print("---> The given destination IPv6 address is invalid. Try again!!!")
            sys.exit(1)

    # Validate the source MAC address
    if args.source_mac is None:
        args.source_mac = get_if_hwaddr(args.interface)
    if args.source_mac is not None:
        if not is_valid_mac(args.source_mac):
            print("---> The given source MAC address is invalid. Try again!!!")
            sys.exit(1)

    # Validate the number of packets
    if args.num_packets is None:
        args.num_packets = 1
    if args.num_packets is not None:
        if not is_valid_num(args.num_packets):
            print("---> The given number of packets is invalid. Try again!!!")
            sys.exit(1)

    # Get the content of file
    if args.filename is not None:
        with open(args.filename, 'rb') as f:
            content = f.read()
            f.close()
    if args.data_length is not None:
        if not is_valid_port(args.data_length):
            print("---> The given size of data is invalid. Try again!!!")
            sys.exit(1)

    stats = psutil.net_if_stats()
    mtu = stats.get(args.interface).mtu
    if args.filename is None:
        data = payload(args.data_length)
    if args.filename is not None and args.data_length is None:
        data = content
    if args.filename is not None and args.data_length is not None:
        if len(content) >= args.data_length:
            data = content[:args.data_length]
        if len(content) < args.data_length:
            data = content + payload(args.data_length - len(args.filename)).encode("utf-8")
            print("---> Warning: The size of file is smaller than the data length, Padding exists at the end of data")

    # Validate the size of Payload data
    if args.data_length is None:
        args.data_length = 32

    # Generate the packet
    id = RandShort()
    if not args.flood:  # Normal situation
        for i in range(args.num_packets):
            packet1 = Ether(src=args.source_mac) / IPv6(src=args.source_ip, dst=args.destination_ip, hlim=128) / \
                      ICMPv6EchoRequest(id=id, seq=i + 1, data=data)
            sendp(fragment6(packet1, mtu), verbose=False, iface=args.interface)
        print("Sending Echo Request message(s) to the destination: " + args.destination_ip)

    if args.flood:  # Flooding the target
        pkt_list = []
        print("Flooding the destination: " + args.destination_ip + " with PING messages (press Ctrl+C to stop the "
                                                                   "attack).....")
        packet1 = Ether(src=args.source_mac) / IPv6(src=args.source_ip, dst=args.destination_ip, hlim=128) / \
                  ICMPv6EchoRequest(data=data)
        packet1 = fragment6(packet1, mtu)
        for i in range(5000):
            pkt_list.append(packet1)
        try:
            sendpfast(pkt_list, mbps=60000, loop=5000000, iface=args.interface)
        except KeyboardInterrupt:
            sys.exit(0)


if __name__ == "__main__":
    main()
