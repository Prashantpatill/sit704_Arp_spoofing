
from scapy.all import *
from scapy.layers.l2 import ARP
packets = rdpcap('ARPSPOOF.pcapng')
# creating a dictionary to have our IP address with it respective mac address
mactable =\
{
    "192.168.1.1" : "08:00:27:8d:3f:07", # ip address and Mac address of the Router
    "192.168.1.109" : "08:00:27:a1:a7:67", # ip address and Mac address of the Victim
    "192.168.1.112" : " 08:00:27:cb:52:6c" # ip address and Mac address of the Attacker
}
def possibleArpAttack(packet):
    if ARP in packet:
        sourceIpAddress=packet[ARP].psrc # Extract the source IP address from the arppacket where psrc is a variable from the library scapy
        sourceMacAddrees = packet[ARP].hwsrc # Extract the source MAC address from the arppacket where psrc is a variable from the library scapy

        if sourceIpAddress in mactable: # Condition to check if the ipaddress that we extracted from the arp packet is present in our dictionary mactable that we created in line 6
            if sourceMacAddrees != mactable[sourceIpAddress]: # condition to check if the MAC address extracted from the arp packet is same as the one we have in our dictionary
                print(f"Hey User a probable ARP Spoofing has happened at {sourceIpAddress},Expected Mac: {mactable[sourceIpAddress]}, Received MAC: {sourceMacAddrees}")

            else:
                mactable[sourceIpAddress]=sourceMacAddrees

for packetindex in packets:
 if packetindex.haslayer(ARP):
     arpAttack=possibleArpAttack(packetindex)
