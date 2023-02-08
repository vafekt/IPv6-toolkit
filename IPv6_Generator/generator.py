#!/usr/bin/python
from datetime import datetime
from scapy.arch import get_if_addr
from scapy.config import conf
from echoRequest import echoRequest
from mldv2_Query import mldv2_Query
from mldv2_Report import mldv2_Report
from routingHeader import routingHeader
from destinationHeader import destinationHeader
from fragmentHeader import fragmentHeader
from toobigMTU import toobigMTU
from timeExceeded import timeExceeded
from reconnaisance import reconnaisance
from smurf import smurf
from covertChannel import covertChannel
from redirect import redirect
from flood_RouterAlert import flood_RouterAlert
from flood_redirect import flood_redirect
from flood_RA import flood_RA
from flood_NS import flood_NS
from flood_DHCPv6 import flood_DHCPv6
from defaultRouter_RA import defaultRouter_RA
from prefixRouter_RA import prefixRouter_RA
from killRouter_RA import killRouter_RA
from spoof_NA import spoof_NA
from resolve_NS import resolve_NS
from dad import dad
from dhcpv6_Server import dhcpv6_Server

now = datetime.now()
current_time = now.strftime("%H:%M:%S")
current_date = now.strftime("%d/%m/%Y")

# Print the date and time when launching. Then address specification
print("Starting IPv6 Generator (https://github.com/vafekt/IPv6-generator.git) at", current_date, current_time)
print("------------------------------------------------------------------------")
print("Address specification from working interfaces of your host is: (VMware prefix means 00:0c:29)")
get_if_addr("eth0")
print(conf.ifaces)
print("------------------------------------------------------------------------")
print("Choose one option below, insert the number (1, 2, 3,...):\n "
      "[1]:  Sending an ICMPv6 Echo Request packet from a given source IPv6 address to a given destination IPv6 "
      "address.\n "
      "[2]:  Sending one of two types of MLDv2 messages (MLDv2 Query, Report).\n "
      "[3]:  Sending an ICMPv6 Echo Request message through Routing Header with a given source, destination and "
      "intermediate hops.\n "
      "[4]:  Sending SYN packets containing Destination Option Header with options (Destination Header with empty "
      "padding, multiple Destination Option Headers).\n "
      "[5]:  Sending SYN packets or ICMPv6 Echo Request messages containing Fragment Header with several options ("
      "atomic, 3x atomic, 100x atomic, tiny fragments and overlapping).\n "
      "[6]:  Implanting the specified MTU on a given target from a given node.\n "
      "[7]:  Causing Time Exceeded problem from a given source IPv6 address to a given destination IPv6 address.\n "
      "[8]:  Detecting all alive nodes on the attached link (Reconnaissance).\n "
      "[9]:  Generating Smurf attack on a specified target by many ICMPv6 Echo Reply message from other hosts.\n "
      "[10]: Sending a message with Covert channel which can bypass the firewall.\n "
      "[11]: Sending a Redirect message to change network traffic from a given old router to the new one.\n "
      "[12]: Triggering Flood attack with options.\n "
      "[13]: Announcing a specified target as the default router on the attached link.\n "
      "[14]: Making every host on the link autoconfigure IPv6 address and get other information based on specified "
      "IPv6 prefix and other information.\n "
      "[15]: Killing a specified default router on the link.\n "
      "[16]: Generating spoofing attack with falsified Neighbor Advertisement message.\n "
      "[17]: Generating spoofing attack with falsified Neighbor Solicitation message.\n "
      "[18]: Triggering DAD (Duplicate Address Detection) process on the link.\n "
      "[19]: Configuring as a DHCPv6 server.\n ")

# Choose the option
number = int(input("Insert your number of option: "))


def num_option(num):
    match num:
        case 1:  # ICMPv6 Echo Request
            interface = input("- Insert the interface, if you skip this by Enter, the packet is automatically sent on "
                              "every active interface: ")
            smac = input("- Insert the source MAC address, if you skip this by Enter, the MAC address of sender is "
                         "automatically resolved from the source IPv6 address: ")
            sip = input("- Insert the source IPv6 address: ")
            dip = input("- Insert the destination IPv6 address: ")
            echoRequest(interface, smac, sip, dip)
        case 2:  # MLDv2
            num_message = int(input("Choose type of message: Query (insert 1), Report (insert 2): "))
            match num_message:
                case 1:  # Query MLDv2
                    interface = input("- Insert the interface, if you skip this by Enter, the packet is automatically "
                                      "sent on every active interface: ")
                    smac = input("- Insert the source MAC address, if you skip this by Enter, the MAC address of your "
                                 "host is "
                                 "automatically resolved from the source IPv6 address: ")
                    sip = input("- Insert the source IPv6 address: ")
                    dip = input("- Insert the destination IPv6 address: ")
                    mulip = input("- Insert the multicast address (the address which is of interest to those "
                                  "neighboring nodes): ")
                    num_sources = int(input("- Insert number of sources (It is set to 0 in General Query and "
                                            "Multicast Address Specific Query, non-zero in Multicast Address and "
                                            "Source Specific Query): "))
                    mldv2_Query(interface, smac, sip, dip, mulip, num_sources)
                case 2:  # Report MLDv2
                    interface = input("- Insert the interface, if you skip this by Enter, the packet is automatically "
                                      "sent on every active interface: ")
                    smac = input("- Insert the source MAC address, if you skip this by Enter, the MAC address of your "
                                 "host is "
                                 "automatically resolved from the source IPv6 address: ")
                    sip = input("- Insert the source IPv6 address: ")
                    dip = input("- Insert the destination IPv6 address (ff02::16 for all MLDv2 routers): ")
                    num_records = int(input("- Insert how many Multicast Address Records are present in the Report "
                                            "message: "))
                    mldv2_Report(interface, smac, sip, dip, num_records)
        case 3:  # Routing Header
            interface = input("- Insert the interface, if you skip this by Enter, the packet is automatically "
                              "sent on every active interface: ")
            smac = input("- Insert the source MAC address, if you skip this by Enter, the MAC address of sender is "
                         "automatically resolved from the source IPv6 address: ")
            sip = input("- Insert the source IPv6 address: ")
            dip = input("- Insert the destination IPv6 address: ")
            num_hops = int(input("- Insert how many intermediate hops (Routing header works when the last hop is the "
                                 "final destination): "))
            routingHeader(interface, smac, sip, dip, num_hops)
        case 4:  # Destination Option Header
            interface = input("- Insert the interface, if you skip this by Enter, the packet is automatically "
                              "sent on every active interface: ")
            smac = input("- Insert the source MAC address, if you skip this by Enter, the MAC address of sender is "
                         "automatically resolved from the source IPv6 address: ")
            sip = input("- Insert the source IPv6 address: ")
            dip = input("- Insert the destination IPv6 address: ")
            sport = input("- Insert the source port, if you skip this by Enter, the source port of sender is "
                          "automatically randomized: ")
            dport = int(input("- Insert the destination port: "))
            destinationHeader(interface, smac, sip, dip, sport, dport)
        case 5:  # Fragment Header
            interface = input("- Insert the interface, if you skip this by Enter, the packet is automatically "
                              "sent on every active interface: ")
            smac = input("- Insert the source MAC address, if you skip this by Enter, the MAC address of sender is "
                         "automatically resolved from the source IPv6 address: ")
            sip = input("- Insert the source IPv6 address: ")
            dip = input("- Insert the destination IPv6 address: ")
            sport = input("- Insert the source port, if you skip this by Enter, the source port of sender is "
                          "automatically randomized: ")
            dport = int(input("- Insert the destination port: "))
            fragmentHeader(interface, smac, sip, dip, sport, dport)
        case 6:  # Packet Too Big
            interface = input("- Insert the interface, if you skip this by Enter, the packet is automatically "
                              "sent on every active interface: ")
            tip = input("- Insert the target IPv6 address: ")
            sip = input("- Insert the IPv6 address of host, which sends Packet Too Big message to the target: ")
            mtu = int(input("- Insert the MTU in the Packet Too Big message: "))
            toobigMTU(interface, tip, sip, mtu)
        case 7:  # Time Exceeded
            interface = input("- Insert the interface, if you skip this by Enter, the packet is automatically "
                              "sent on every active interface: ")
            smac = input("- Insert the source MAC address, if you skip this by Enter, the MAC address of sender is "
                         "automatically resolved from the source IPv6 address: ")
            sip = input("- Insert the source IPv6 address: ")
            dip = input("- Insert the destination IPv6 address: ")
            hop = input("- Insert the IPv6 address of the hop that sends Time Exceeded message back to the sender: ")
            timeExceeded(interface, smac, sip, dip, hop)
        case 8:  # Reconnaissance
            interface = input("- Insert the active interface: ")
            reconnaisance(interface)
        case 9:  # Smurf attack
            interface = input("- Insert the interface, if you skip this by Enter, the packet is automatically "
                              "sent on every active interface: ")
            tip = input("- Insert the target IPv6 address: ")
            smurf(interface, tip)
        case 10:  # Covert channel
            interface = input("- Insert the interface, if you skip this by Enter, the packet is automatically "
                              "sent on every active interface: ")
            smac = input("- Insert the source MAC address, if you skip this by Enter, the MAC address of sender is "
                         "automatically resolved from the source IPv6 address: ")
            sip = input("- Insert the source IPv6 address: ")
            dip = input("- Insert the destination (victim) IPv6 address: ")
            sport = input("- Insert the source port, if you skip this by Enter, the source port of sender is "
                          "automatically randomized: ")
            dport = int(input("- Insert the destination port: "))
            covertChannel(interface, smac, sip, dip, sport, dport)
        case 11:  # Redirect
            interface = input("- Insert the interface, if you skip this by Enter, the packet is automatically "
                              "sent on every active interface: ")
            sip = input("- Insert the source (target host) IPv6 address: ")
            dip = input("- Insert the destination IPv6 address: ")
            old_router = input("- Insert the IPv6 address of the old router: ")
            new_router = input("- Insert the IPv6 address of the new router that you want to change traffic to: ")
            mac_router = input("- Insert the MAC address of that new router: ")
            redirect(interface, sip, dip, old_router, new_router, mac_router)
        case 12:  # Flood attack
            num_attack = int(input("Choose one type of Flood attacks:\n "
                                   "1: Flooding the specified router with enormous falsified Router Alert messages.\n "
                                   "2: Preventing network traffic from a specified victim with enormous falsified "
                                   "Redirect messages.\n "
                                   "3: Flooding and poisoning cache of all hosts on the link with enormous falsified "
                                   "Router Advertisement messages.\n "
                                   "4: Flooding the specified host with enormous falsified Neighbor Solicitation "
                                   "messages.\n "
                                   "5: Flooding the specified DHCPv6 server with enormous falsified DHCPv6 Solicit "
                                   "messages.\n "
                                   "Insert one of 5 options (1, 2, 3,...): "))
            match num_attack:
                case 1:  # Router Alert flood
                    flood_RouterAlert()
                case 2:  # Redirect flood
                    flood_redirect()
                case 3:  # RA flood
                    flood_RA()
                case 4:  # NS flood
                    flood_NS()
                case 5:  # DHCPv6 Solicit flood
                    flood_DHCPv6()
        case 13:  # Default router RA
            interface = input("- Insert the interface, if you skip this by Enter, the packet is automatically "
                              "sent on every active interface: ")
            smac = input("- Insert the target MAC address, if you skip this by Enter, the MAC address of sender is "
                         "automatically resolved from the source IPv6 address: ")
            sip = input("- Insert the target IPv6 address: ")
            router_lifetime = input("- Insert the router lifetime, if you skip this by Enter, the lifetime is set "
                                    "to the default value: ")
            defaultRouter_RA(interface, smac, sip, router_lifetime)
        case 14:  # Bogus IPv6
            interface = input("- Insert the interface, if you skip this by Enter, the packet is automatically "
                              "sent on every active interface: ")
            smac = input("- Insert the target (default router) MAC address, if you skip this by Enter, the MAC "
                         "address of sender is automatically resolved from the source IPv6 address: ")
            sip = input("- Insert the target (default router) IPv6 address: ")
            prefix_len = int(input("- Insert the prefix length: "))
            prefix = input("- Insert the IPv6 prefix: ")
            router_lifetime = input("- Insert the router lifetime, if you skip this by Enter, the lifetime is set "
                                    "to the default value: ")
            dns_ip = input("- Insert the IPv6 address of DNS server, if you skip this by Enter, no DNS server is "
                           "included: ")
            prefixRouter_RA(interface, smac, sip, prefix_len, prefix, router_lifetime, dns_ip)
        case 15:  # Kill router
            interface = input("- Insert the interface, if you skip this by Enter, the packet is automatically "
                              "sent on every active interface: ")
            smac = input("- Insert the target (default router) MAC address, if you skip this by Enter, the MAC "
                         "address of sender is automatically resolved from the source IPv6 address: ")
            sip = input("- Insert the target (default router) IPv6 address: ")
            killRouter_RA(interface, smac, sip)
        case 16:  # Spoof NA
            interface = input("- Insert the interface, if you skip this by Enter, the packet is automatically "
                              "sent on every active interface: ")
            smac = input("- Insert the attacker MAC address: ")
            spoof_NA(interface, smac)
        case 17:  # Spoof NS
            interface = input("- Insert the interface, if you skip this by Enter, the packet is automatically "
                              "sent on every active interface: ")
            smac = input("- Insert the attacker MAC address, if you skip this by Enter, the MAC "
                         "address of sender is automatically resolved from the attacker IPv6 address: ")
            sip = input("- Insert the attacker IPv6 address: ")
            tip = input("- Insert the target IPv6 address: ")
            vip = input("- Insert the spoofed host's IPv6 address: ")
            vmac = input("- Insert the attacker MAC address, if you skip this by Enter, the MAC "
                         "address of sender is automatically resolved from the spoofed host's IPv6 address: ")
            resolve_NS(interface, smac, sip, tip, vip, vmac)
        case 18:  # DAD process
            interface = input("- Insert the interface, if you skip this by Enter, the packet is automatically "
                              "sent on every active interface: ")
            dad(interface)
        case 19:  # DHCPv6 server
            interface = input("- Insert the interface, if you skip this by Enter, the packet is automatically "
                              "sent on every active interface: ")
            smac = input("- Insert the source (server) MAC address, if you skip this by Enter, the MAC address of "
                         "sender is automatically resolved from the source IPv6 address: ")
            sip = input("- Insert the source (server) IPv6 address: ")
            prefix_len = int(input("- Insert the prefix length: "))
            network_address = input("- Insert the network address of the pool: ")
            dns_ip = input("- Insert the IPv6 address of DNS server: ")
            dhcpv6_Server(interface, smac, sip, network_address, prefix_len, dns_ip)

num_option(number)
