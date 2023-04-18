#!/usr/bin/env python3
import argparse
import logging
import multiprocessing
import random
import sys
import threading

import netifaces as ni
import netifaces
import psutil
from scapy.arch import get_if_hwaddr
from scapy.config import conf
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6, fragment6, ICMPv6EchoReply, ICMPv6ParamProblem, \
    ICMPv6DestUnreach, ICMPv6TimeExceeded, ICMPv6PacketTooBig, IPv6ExtHdrFragment, ICMPv6ND_NA, ICMPv6ND_NS
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sendpfast, sndrcvflood, srpflood, sniff
from scapy.supersocket import SuperSocket
from scapy.volatile import RandString, RandShort
from validate_parameters import is_valid_ipv6, validate_file, is_valid_port, convert_paramProblem, \
    convert_destUnrechable, convert_timeExceeded
from validate_parameters import is_valid_mac
from validate_parameters import is_valid_num
from validate_parameters import payload


def parameter():
    parser = argparse.ArgumentParser(description="|> Sending PING (ICMPv6 Echo Request) message(s) from a given source "
                                                 "IPv6 address to a given destination IPv6 address with specified "
                                                 "number of packets, size of data and option to flood.")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender.")
    parser.add_argument("-smac", dest="source_mac", action="store",
                        help="the MAC address of sender (resolved from the interface if skipping).")
    parser.add_argument("-dmac", dest="destination_mac", action="store",
                        help="the MAC address of receiver (resolved from the interface if skipping).")
    parser.add_argument("-sip", dest="source_ip", action="store", help="the IPv6 address of sender (resolved from the"
                                                                       " interface if skipping).")
    parser.add_argument("-dip", dest="destination_ip", action="store", help="the IPv6 address of destination (ff02::1"
                                                                            " if skipping).")
    parser.add_argument("-hlim", dest="hop_lim", action="store", type=int,
                        help="the hop limit of PING message (255 if skipping).")
    parser.add_argument("-n", dest="num_packets", action="store", default=1, type=int,
                        help="the number of packets to send (1 if skipping).")
    parser.add_argument("-l", dest="data_length", type=int, action="store",
                        help="the size of data in bytes (32 if skipping).")
    parser.add_argument("-i", dest="filename", action="store", type=validate_file,
                        help="input file to send (not influenced by parameter -l if being set).", metavar="FILE")
    parser.add_argument("-f", dest="flood", action="store", choices=['constant', 'random'],
                        help="flood the targets with option: sending Request messages using only the defined "
                             "source addresses (constant), or sending Request messages with many random source "
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

    # Validate the destination MAC address
    if args.destination_mac is not None:
        if not is_valid_mac(args.destination_mac):
            print("---> The given destination MAC address is invalid. Try again!!!")
            sys.exit(1)

    # Validate the hop limit
    if args.hop_lim is None:
        args.hop_lim = 255
    if args.hop_lim is not None:
        if args.hop_lim < 0 or args.hop_lim > 255:
            print("---> The given number of hop limit is invalid. Try again!!!")
            sys.exit(1)

    # Validate the number of packets
    if args.num_packets is None:
        args.num_packets = 1
    if args.num_packets is not None:
        if not is_valid_num(args.num_packets):
            print("---> The given number of packets is invalid. Try again!!!")
            sys.exit(1)

    # Validate the size of Payload data
    if args.data_length is None:
        args.data_length = 32
    if args.data_length is not None:
        if not is_valid_port(args.data_length):
            print("---> The given size of data is invalid. Try again!!!")
            sys.exit(1)
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

    # Turning off logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    return args.interface, args.source_mac, args.destination_mac, args.source_ip, args.destination_ip, args.hop_lim, args.num_packets, data, args.flood


def generate(interface, source_mac, destination_mac, source_ip, destination_ip, hop_lim, num_packets, data, flood):
    # Generate the packet
    id = RandShort()
    stats = psutil.net_if_stats()
    mtu = stats.get(interface).mtu

    if destination_mac is None:
        layer2 = Ether(src=source_mac)
    if destination_mac is not None:
        layer2 = Ether(src=source_mac, dst=destination_mac)

    if flood is None:  # Normal situation
        print("Sending Echo Request message(s) to the destination: " + destination_ip)
        for i in range(num_packets):
            packet1 = layer2 / IPv6(src=source_ip, dst=destination_ip, hlim=hop_lim) / ICMPv6EchoRequest(id=id, seq=i + 1, data=data)
            if len(data) > mtu:  # Fragmentation exists
                sendp(fragment6(packet1, mtu), verbose=False, iface=interface)
            else:
                sendp(packet1, verbose=False, iface=interface)

    if flood is not None:  # Flooding the target
        pkt_list = []
        print("Flooding the destination: " + destination_ip + " with PING messages (press Ctrl+C to stop the "
                                                              "attack).....")
        if flood == "constant":
            for i in range(150):
                packet1 = layer2 / IPv6(src=source_ip, dst=destination_ip,
                                                       hlim=hop_lim) / ICMPv6EchoRequest(id=id, seq=i + 1, data=data)
                if len(data) > mtu:  # Fragmentation exists
                    packet1 = fragment6(packet1, mtu)
                pkt_list.append(packet1)
        if flood == "random":
            for i in range(70):
                random_mac = "02:01:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                                          random.randint(0, 255),
                                                          random.randint(0, 255))
                M = 16 ** 4
                source_ip = "2001:dead:" + ":".join(("%x" % random.randint(0, M) for j in range(6)))
                packet1 = Ether(src=random_mac) / IPv6(src=source_ip, dst=destination_ip,
                                                       hlim=hop_lim) / ICMPv6EchoRequest(id=id, seq=i + 1, data=data)
                if len(data) > mtu:  # Fragmentation exists
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

    def custom_action(packet):
        # Create tuple of Src/Dst in sorted order
        if ICMPv6ND_NA not in packet or ICMPv6ND_NS not in packet:
            if ICMPv6EchoReply or IPv6ExtHdrFragment in packet:
                print("===> Received Echo Reply from: " + packet[0][1].src + "\n                     with MAC: " + packet[0].src)
                ip_list.append(packet[0][1].src)
            if ICMPv6ParamProblem in packet:
                print("===> Received Parameter Problem from: " + packet[0][1].src + " with MAC: " + packet[0].src)
                print("     with error: " + convert_paramProblem(packet[ICMPv6ParamProblem].code))
                ip_list.append(packet[0][1].src)
            if ICMPv6DestUnreach in packet:
                print("===> Received Destination Unreachable from: " + packet[0][1].src + " with MAC: " + packet[0].src)
                print("     with error: " + convert_destUnrechable(packet[ICMPv6DestUnreach].code))
                ip_list.append(packet[0][1].src)
            if ICMPv6TimeExceeded in packet:
                print("===> Received Time Exceeded from: " + packet[0][1].src + " with MAC: " + packet[0].src)
                print("     with error: " + convert_timeExceeded(packet[ICMPv6TimeExceeded].code))
                ip_list.append(packet[0][1].src)
            if ICMPv6PacketTooBig in packet:
                print("===> Received Packet Too Big from: " + packet[0][1].src + " with MAC: " + packet[0].src)
                print("     with informed MTU: " + str(packet[ICMPv6PacketTooBig].mtu))
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


def execute_functions(interface, source_mac, destination_mac, source_ip, destination_ip, hop_lim, num_packets, data, flood):
    p1 = multiprocessing.Process(target=generate, args=[interface, source_mac, destination_mac, source_ip, destination_ip, hop_lim, num_packets, data, flood])
    p2 = multiprocessing.Process(target=sniffing, args=[interface, source_ip, destination_ip])
    p2.start()
    p1.start()
    p2.join()
    p1.join()


if __name__ == "__main__":
    interface, source_mac, destinatino_mac, source_ip, destination_ip, hop_lim, num_packets, data, flood = parameter()
    if flood is None:
        try:
            execute_functions(interface, source_mac, destinatino_mac, source_ip, destination_ip, hop_lim, num_packets, data, flood)
        except KeyboardInterrupt:
            sys.exit(0)
    else:
        try:
            generate(interface, source_mac, destinatino_mac, source_ip, destination_ip, hop_lim, num_packets, data, flood)
        except KeyboardInterrupt:
            # If KeyboardInterrupt is raised in the main thread, stop all child threads
            threading.Event().set()
            sys.exit(0)
