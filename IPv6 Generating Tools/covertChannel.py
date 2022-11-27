#!/usr/bin/python
import sys
from scapy.layers.inet import TCP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrDestOpt, PadN
from scapy.sendrecv import send
from scapy.volatile import RandShort

# Ask user to insert value
if len(sys.argv) == 3:
    attacker_ip = sys.argv[1]
    victim_ip = sys.argv[2]
else:
    print("Please insert:\n 1. Source IPv6 address\n 2. Destination IPv6 address.")
    sys.exit(1)

# Generate packet
data1 = "https://github.com/secdev/scapy/blob/master/scapy/layers/inet6.py"
data2 = "https://www.youtube.com/watch?v=hVy8lp2JzPE"
data3 = "https://samsclass.info/ipv6/proj/fw6a.htm"
data4 = "file:///E:/STUDIUM/PRVN%C3%8D%20LETN%C3%8D%20SEMESTR"
data5 = "https://www.google.com/search?client=firefox-b-d&q=slaac+scapy"
layer3 = IPv6(src=attacker_ip, dst=victim_ip)
Extension = IPv6ExtHdrDestOpt(options=[PadN(optdata=data1)] +
                                      [PadN(optdata=data2)] +
                                      [PadN(optdata=data3)] +
                                      [PadN(optdata=data4)])

packet1 = layer3/Extension/TCP(sport=RandShort(), dport=80)/data5
send(packet1, verbose=False)
print("Sending packet with covert message inside the extension headers to address: " + victim_ip)
