#!/usr/bin/python3
import argparse
import multiprocessing
import sys
from collections import Counter

import netifaces
from scapy.arch import get_if_hwaddr
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, IPv6ExtHdrDestOpt, HBHOptUnknown, Pad1
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sniff


def main():
    parser = argparse.ArgumentParser(description="Detecting all alive hosts on the attached local link.")
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

    # Getting the IPv6 address and MAC from source
    source_ip_1 = netifaces.ifaddresses(args.interface)[netifaces.AF_INET6][-1]['addr']
    source_ip_1 = source_ip_1.replace("%", '')
    source_ip_1 = source_ip_1.replace(args.interface, '')

    source_ip_2 = netifaces.ifaddresses(args.interface)[netifaces.AF_INET6][0]['addr']
    source_ip_2 = source_ip_2.replace("%", '')
    source_ip_2 = source_ip_2.replace(args.interface, '')
    source_mac = get_if_hwaddr(args.interface)

    return args.interface, source_ip_1, source_ip_2, source_mac


def generate(interface, source_ip1, source_ip2, source_mac):
    # Generate the packets
    data = "A" * 8
    packet1 = Ether(src=source_mac) / IPv6(src=source_ip1, dst="ff02::1") / ICMPv6EchoRequest()
    wrong_extension = IPv6ExtHdrDestOpt(options=[HBHOptUnknown(otype=128)] + [Pad1()] + [Pad1()] + [Pad1()])
    packet2 = Ether(src=source_mac) / IPv6(src=source_ip1, dst="ff02::1") / wrong_extension / ICMPv6EchoRequest(
        data=data)

    packet3 = Ether(src=source_mac) / IPv6(src=source_ip2, dst="ff02::1") / ICMPv6EchoRequest()
    wrong_extension = IPv6ExtHdrDestOpt(options=[HBHOptUnknown(otype=128)] + [Pad1()] + [Pad1()] + [Pad1()])
    packet4 = Ether(src=source_mac) / IPv6(src=source_ip2, dst="ff02::1") / wrong_extension / ICMPv6EchoRequest(
        data=data)
    # Sending 1 normal, 1 Parameter Problem packet

    # try:
    for i in range(3):
        try:
            sendp([packet1, packet2, packet3, packet4], verbose=False, iface=interface)
        except KeyboardInterrupt:
            sys.exit(0)


def sniffing(interface, source_ip1, source_ip2):
    # Define our Custom Action function
    packet_counts = Counter()
    ip_list = []
    mac_list = []

    def custom_action(packet):
        # Create tuple of Src/Dst in sorted order
        if packet[0][1].src not in ip_list:  # Deleting duplicate address when capturing
            key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
            packet_counts.update([key])
            ip_list.append(packet[0][1].src)
            if packet[0].src not in mac_list:
                mac_list.append(packet[0].src)
            return f"Discover the IPv6 address number #{sum(packet_counts.values())}: " \
                   f"{packet[0][1].src} with MAC: {packet[0].src}"

    # Setup sniff, filtering for IP traffic to see the result
    print("Initializing to detect active hosts on the link.....")
    build_filter = "ip6 dst %s or %s" % (source_ip1, source_ip2)

    try:
        sniff(iface=interface, filter=build_filter, prn=custom_action, timeout=5)
    except KeyboardInterrupt:
        sys.exit(0)
    num_hosts = len(mac_list)
    print("===> Found: " + str(num_hosts) + " alive host(s) on the local link.")


iface, sip1, sip2, smac = main()
p1 = multiprocessing.Process(target=generate, args=[iface, sip1, sip2, smac])
p2 = multiprocessing.Process(target=sniffing, args=[iface, sip1, sip2])

p1.start()
p2.start()

