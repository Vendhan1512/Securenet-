# FIX APPLIED - BASELINE_TIMESTAMP ADDED

## Problem Found & Fixed
```
ERROR: NetworkBaseline.__init__() missing 1 required positional argument: 'baseline_timestamp'
```

## Solution Applied ✅
Added `baseline_timestamp=datetime.now()` to NetworkBaseline initialization in production_system.py

The file has been synced to Monitor VM.

---

## MANUAL RESTART PROCEDURE (on Monitor VM)

You must manually restart because non-interactive SSH has sudo password issues. 

**SSH into Monitor VM:**
```bash
ssh -o StrictHostKeyChecking=no monitor@192.168.128.8
Password: achu2006
```

**On Monitor terminal:**
```bash
# If you see interactive console, type:
quit

# Then:
cd ~/securenet
sudo pkill -9 -f "python3.*production_main" 2>/dev/null || true
sleep 2

# Clear old logs
rm -f production_security.log

# Start in interactive mode
sudo python3 production_main.py --interactive --interface enp0s1 --config production_config.yaml --log-level INFO
```

**Expected output (within 5 seconds):**
```
✅ Production system initialized successfully
🛡️ Starting network monitoring on enp0s1
Monitoring active...
```

**In NEW terminal, verify baseline:**
```bash
ssh -o StrictHostKeyChecking=no monitor@192.168.128.8
grep "baseline" ~/securenet/production_security.log
```

Should show:
```
INFO - Detector baselines initialized (DNS, ARP, CAM)
```

---

## THEN: Run DNS Attack Again
```bash
# On Attacker VM:
sudo python3 ~/run_dns_attack.py
```

## THEN: Check for Alert
```bash
# On Monitor VM:
tail -f ~/securenet/production_security.log | grep -i "dns\|spoofing"
```

Should see within 5-30 seconds:
```
ATTACK DETECTED: DNS_SPOOFING
Confidence: 0.75
Detection: ANOMALY_BASED
```

---

**The fix is ready. You just need to manually restart Monitor!**
