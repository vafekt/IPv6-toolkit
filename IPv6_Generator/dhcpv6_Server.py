#!/usr/bin/python
import random
import sys
from scapy.layers.dhcp6 import DHCP6_Solicit, DHCP6_Advertise, DHCP6OptClientId, DUID_LLT, DHCP6OptServerId, \
    DHCP6OptDNSServers, DHCP6OptIA_NA, DHCP6OptIAAddress, DHCP6_Request, DHCP6_Reply
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptMTU, \
    ICMPv6NDOptRDNSS, getmacbyip6
from scapy.layers.l2 import Ether
from scapy.sendrecv import send, sniff, sendp


def dhcpv6_Server(interface, smac, sip, network_address, prefix_len, dns_ip):
    if smac == "":
        smac = getmacbyip6(sip)
    # Generate Router Advertisement message
    layer3_RA = IPv6(src=sip, dst="ff02::1")
    # network_address = network_address + "::"
    packet_RA = Ether(src=smac) / layer3_RA / ICMPv6ND_RA(prf="High", M=1, O=1, routerlifetime=350) / \
                ICMPv6NDOptMTU(mtu=1500) / \
                ICMPv6NDOptSrcLLAddr(lladdr=smac) / \
                ICMPv6NDOptPrefixInfo(prefixlen=prefix_len, A=0,
                                      validlifetime=0x12c,
                                      preferredlifetime=0x96,
                                      prefix=network_address) / \
                ICMPv6NDOptRDNSS(dns=[dns_ip])
    if interface == "":
        sendp(packet_RA, verbose=False)
    else:
        sendp(packet_RA, verbose=False, iface=interface)

    def change_send(pkt):
        if DHCP6_Solicit in pkt:
            server_duid = DUID_LLT(type=1, hwtype=1, timeval=pkt[DHCP6OptClientId].duid.timeval + 9050,
                                   lladdr=smac)
            M = 16 ** 4
            addr_server = network_address + ":" + "".join(("%x" % random.randint(0, M)
                                                           for j in range(1))) + "::"
            layer3 = IPv6(src=sip, dst=pkt[IPv6].src)
            layer4 = UDP(sport=547, dport=546)
            advertise = DHCP6_Advertise(trid=pkt[DHCP6_Solicit].trid)
            clientID = DHCP6OptClientId(duid=pkt[DHCP6OptClientId][1])
            serverID = DHCP6OptServerId(duid=server_duid)
            dnsServer = DHCP6OptDNSServers(dnsservers=[dns_ip])
            ia_na = DHCP6OptIA_NA(iaid=369101865, T1=32512, T2=65024,
                                  ianaopts=DHCP6OptIAAddress(optcode=5, optlen=24,
                                                             addr=addr_server,
                                                             preflft=131072,
                                                             validlft=131072))
            if interface == "":
                sendp(Ether(src=smac) / layer3 / layer4 / advertise / clientID / serverID / dnsServer / ia_na, verbose=False)
            else:
                sendp(Ether(src=smac) / layer3 / layer4 / advertise / clientID / serverID / dnsServer / ia_na, verbose=False, iface=interface)
            print("Send DHCP Advertisement to client with link-local IPv6 address: ", pkt[IPv6].src)
        if DHCP6_Request in pkt:
            layer3 = IPv6(src=sip, dst=pkt[IPv6].src)
            layer4 = UDP(sport=547, dport=546)
            reply = DHCP6_Reply(trid=pkt[DHCP6_Request].trid)
            clientID = DHCP6OptClientId(duid=pkt[DHCP6OptClientId][1])
            serverID = DHCP6OptServerId(duid=pkt[DHCP6OptServerId][1])
            ia_na = DHCP6OptIA_NA(iaid=369101865, T1=32512, T2=65024,
                                  ianaopts=pkt[DHCP6OptIA_NA].ianaopts)
            dnsServer = DHCP6OptDNSServers(dnsservers=[dns_ip])
            if interface == "":
                sendp(Ether(src=smac) / layer3 / layer4 / reply / clientID / serverID / ia_na / dnsServer, verbose=False)
            else:
                sendp(Ether(src=smac) / layer3 / layer4 / reply / clientID / serverID / ia_na / dnsServer,
                      verbose=False, iface=interface)
            print("Send Reply to client with link-local IPv6 address: ", pkt[IPv6].src)

    while True:
        try:
            if interface == "":
                sniff(prn=change_send)
            else:
                sniff(iface=interface, prn=change_send)
        except KeyboardInterrupt:
            break

