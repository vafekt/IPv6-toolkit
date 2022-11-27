#!/usr/bin/python
import sys
from scapy.arch import get_if_addr6, get_if_hwaddr
from scapy.config import conf
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6
from scapy.sendrecv import send
from scapy.volatile import RandShort

# Ask user to insert value
if len(sys.argv) == 3:
    server_ip = sys.argv[1]
    domain_name = sys.argv[2]
else:
    print("Please insert:\n 1. DNS server's IPv6\n 2. Domain name")
    sys.exit(1)

# Get the IPv6 address of our device
sip = get_if_addr6(conf.iface) or "::1"

# Get the MAC address of our device
mac = get_if_hwaddr(conf.iface)

# Generate packet
layer3 = IPv6(src=sip, dst=server_ip)
layer4 = UDP(sport=RandShort(), dport=53)
dns_A = DNS(qd=DNSQR(qname=domain_name, qtype="A"))
dns_AAAA = DNS(qd=DNSQR(qname=domain_name, qtype="AAAA"))
packet1 = layer3/layer4/dns_A
packet2 = layer3/layer4/dns_AAAA
send([packet1, packet2], verbose=False)
print("Sending DNS request with A record and AAAA record for domain name: " + domain_name)

