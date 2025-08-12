from scapy.all import *
import sys

# Known legitimate DNS servers
LEGIT_DNS_SERVERS = ["8.8.8.8", "1.1.1.1"]  # Google & Cloudflare

def detect_dns_spoofing(pkt):
    if pkt.haslayer(DNSRR):  # Check for DNS Response Record
        domain = pkt[DNSQR].qname.decode()
        response_ip = pkt[DNSRR].rdata
        dns_server = pkt[IP].src

        # Check 1: Unexpected DNS server
        if dns_server not in LEGIT_DNS_SERVERS:
            print(f"[!] Suspicious DNS response from {dns_server} for {domain}")

        # Check 2: TTL anomaly (legitimate TTLs are usually > 300)
        if pkt[DNSRR].ttl < 300:
            print(f"[!] Low TTL ({pkt[DNSRR].ttl}) detected for {domain} -> {response_ip}")

        # Check 3: IP mismatch (compare with known legitimate IP)
        if "facebook.com" in domain and response_ip != "157.240.22.35":
            print(f"[!!!] FAKE DNS RESPONSE: {domain} resolves to {response_ip}")

if __name__ == "__main__":
    print("[+] Starting DNS spoofing detector...")
    print("[+] Monitoring for anomalies...")
    sniff(filter="udp and port 53", prn=detect_dns_spoofing, store=0,iface="eth1")
