# MANUAL RESTART & RETEST PROCEDURE

## Problem
DNS baseline initialization not in logs = system not restarted with new code

## Solution
Manually restart Monitor and rerun attack

---

## STEP 1: SSH to Monitor VM (on your Mac)

```bash
ssh -o StrictHostKeyChecking=no monitor@192.168.128.8
Password: achu2006
```

---

## STEP 2: On Monitor VM - Exit current system and restart

```bash
# You should see "production>" prompt
# Type:
quit

# Press Enter
# You should return to bash

# Now restart in daemon mode:
cd ~/securenet
rm -f production_security.log
sudo python3 production_main.py --daemon --interface enp0s1 --config production_config.yaml --log-level INFO

# Wait 5 seconds
sleep 5

# Check if baseline initialized:
grep -i "baseline" production_security.log

# Show last logs:
tail -20 production_security.log
```

Expected output:
```
INFO - Detector baselines initialized (DNS, ARP, CAM)
INFO - Production security system initialized successfully
INFO - Started detection engine on interface enp0s1
```

---

## STEP 3: On Attacker VM - Run DNS attack AGAIN

```bash
# SSH to attacker:
sshpass -p achu2006 ssh -o StrictHostKeyChecking=no attacker@192.168.128.101

# Run attack:
sudo python3 ~/run_dns_attack.py
```

---

## STEP 4: On Monitor VM - Check for DNS_SPOOFING alert

```bash
# Open new terminal/session
ssh -o StrictHostKeyChecking=no monitor@192.168.128.8

# Check logs:
grep -i "dns_spoofing" ~/securenet/production_security.log

# Or watch in real-time:
tail -f ~/securenet/production_security.log | grep -i "dns\|spoofing"
```

Expected output (within 5-30 seconds of attack):
```
2026-01-19 21:15:45 - SECURITY ALERT - CRITICAL - ATTACK DETECTED: DNS_SPOOFING
2026-01-19 21:15:45 - Source IP: 192.168.128.101
2026-01-19 21:15:45 - Confidence: 0.75
2026-01-19 21:15:45 - Detection Method: ANOMALY_BASED
```

---

## If STILL no logs:

Check these diagnostic commands (on Monitor):

```bash
# 1. Is system running?
ps aux | grep "production_main"

# 2. Are logs being created?
ls -lah ~/securenet/production_security.log

# 3. Check for errors:
tail -50 ~/securenet/production_security.log | grep -i "error\|exception"

# 4. Verify interface is correct:
ip link show | grep enp0s1

# 5. Test packet capture:
sudo tcpdump -i enp0s1 'port 53' -n -c 5
```

---

**Run these steps and report back the output!** 🎯
