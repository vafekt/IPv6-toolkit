#!/usr/bin/python3
import argparse
import sys
from collections import Counter
import netifaces
from scapy.layers.inet6 import ICMPv6ND_NS
from scapy.sendrecv import sniff

from validate_parameters import is_valid_num


def main():
    parser = argparse.ArgumentParser(description="Detecting new hosts joining the attached local link based on DAD "
                                                 "process.")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender")
    parser.add_argument("-t", dest='time', type=int, help="the time in seconds to run this attack")
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

    # Validate the time
    if args.time is not None:
        if not is_valid_num(args.time):
            print("---> The given time is invalid. Try again!!!")
            sys.exit(1)

    # Define our Custom Action function
    packet_counts = Counter()
    ip_list = []
    mac_list = []

    def custom_action(packet):
        # Create tuple of Src/Dst in sorted order
        if packet[0][1].src == "::":
            if packet[0][ICMPv6ND_NS].tgt not in ip_list:  # Deleting duplicate address when capturing
                key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
                packet_counts.update([key])
                ip_list.append(packet[0][1].src)
                if packet[0].src not in mac_list:
                    mac_list.append(packet[0].src)
                return f"Detect IPv6 address number #{sum(packet_counts.values())}: " \
                       f"{packet[0][ICMPv6ND_NS].tgt} with MAC: {packet[0].src}"

    # Setup sniff, filtering for IP traffic to see the result
    print("Initializing to detect new IPv6 hosts joining the local link (press Ctrl+C to stop the process).....")
    build_filter = "icmp6 and  ip6[40] == 135"

    if args.time is None:
        try:
            sniff(iface=args.interface, filter=build_filter, prn=custom_action)
        except KeyboardInterrupt:
            sys.exit(0)
    if args.time is not None:
        try:
            sniff(iface=args.interface, filter=build_filter, prn=custom_action, timeout=args.time)
        except KeyboardInterrupt:
            sys.exit(0)

    num_hosts = len(mac_list)
    print("===> Found: " + str(num_hosts) + " host(s) joining local link.\n")


if __name__ == "__main__":
    main()

