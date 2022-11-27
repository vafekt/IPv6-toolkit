#!/usr/bin/python
import sys

from scapy.layers.inet import TCP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.layers.ipsec import SecurityAssociation, AH, ESP
from scapy.sendrecv import send

# Ask user to insert value
if len(sys.argv) == 3:
    sip = sys.argv[1]
    dip = sys.argv[2]
else:
    print("Please insert:\n 1. Source IPv6 address\n 2. Destination IPv6 address")
    sys.exit(1)

a = "my supervisor is the best"
# Define Security Association for AH and ESP in IPsec
SA_AH = SecurityAssociation(AH, spi=0x1234, auth_algo='SHA2-384-192',
                            auth_key=b'my supervisor is the best',
                            crypt_algo='AES-CBC',
                            crypt_key=b'sixteenbytes key')

SA_ESP = SecurityAssociation(ESP, spi=0x1234, auth_algo='SHA2-384-192',
                             auth_key=b'my supervisor is the best',
                             crypt_algo='AES-CBC',
                             crypt_key=b'sixteenbytes key')
# Generate packet
data = "My supervisor teaches both Czech and foreign students."
packet = IPv6(src=sip, dst=dip)/TCP(sport=36251, dport=80)/data
print("The message in open format is: \n-------------------------------")
packet.show2()

# Sign the message
print("Processing AH:"
      "\n--------------------------------")
AH_packet = SA_AH.encrypt(packet)
AH_packet.show2()

# Encryption the payload
print("Processing ESP:"
      "\n--------------------------------")
ESP_packet = SA_ESP.encrypt(AH_packet)
ESP_packet.show2()
send(ESP_packet, verbose=False)
print("\n--------------------------------\nSending encrypted packet to destination: " + dip)

# Decryption
decrypt_packet = SA_ESP.decrypt(ESP_packet)
original_packet = SA_AH.decrypt(decrypt_packet)
print("Decryption:"
      "\n--------------------------------")
original_packet.show2()
