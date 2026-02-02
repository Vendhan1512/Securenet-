# Execution Guide - How to Run SecureNet Automated Setup

## TL;DR - Quick Start

```bash
# 1. Test network
ping -c 1 192.168.100.8

# 2. If network works, run setup
bash scripts/quickstart.sh

# 3. Then use operations
bash scripts/operations.sh
```

---

## Step-by-Step Execution Guide

### STEP 1: Verify Prerequisites

Before starting, make sure:
- All 3 VMs are powered ON (Monitor, Victim, Attacker)
- You can SSH to Monitor VM:
  ```bash
  ssh monitor@192.168.100.8
  ```

### STEP 2: Test Network Connectivity

From your macOS terminal:

```bash
ping -c 1 192.168.100.8
```

**Expected results:**
- ✓ If reply received → Network is good, go to STEP 3
- ✗ If "Request timeout" → Network needs fixing, do STEP 2B

#### STEP 2B: Fix Network (If Needed)

```bash
bash scripts/fix_network.sh
```

This will:
1. Auto-detect your hypervisor
2. Provide hypervisor-specific instructions
3. Guide you through network configuration
4. Test connectivity after fix

---

### STEP 3: Run Complete Automated Setup

**Main command:**

```bash
bash scripts/quickstart.sh
```

**What happens automatically:**

**Phase 1 (~1 min): Network Verification**
- Checks if all 3 VMs are reachable
- Confirms network is ready

**Phase 2 (~3 min): Project Deployment**
- Compresses project files
- SSH to Monitor VM → extracts files
- SSH to Victim VM → extracts files
- SSH to Attacker VM → extracts files

**Phase 3 (~12 min): VM Setup Scripts**
- Runs setup_monitor_vm.sh on Monitor VM
  - Installs detection system
  - Installs dependencies (Python, Scapy, tcpdump)
- Runs setup_victim_vm.sh on Victim VM
  - Installs web server (Apache)
  - Installs network tools
- Runs setup_attacker_vm.sh on Attacker VM
  - Installs attack tools (hping3, Scapy, dsniff)
  - Creates attack scripts (ARP, MAC, DNS spoofing)

**Phase 4 (~3-4 min): Install Dependencies**
- pip3 install on all 3 VMs

**Total Time:** ~20 minutes

**Expected Output:**
- Green checkmarks (✓) showing progress
- Step completion messages
- Next steps displayed at end

---

### STEP 4: Verify Setup Was Successful

```bash
bash scripts/operations.sh connectivity
```

You should see:
```
Monitor VM (192.168.100.8):   ✓
Victim VM (192.168.100.6):    ✓
Attacker VM (192.168.100.101): ✓
```

---

### STEP 5: Create Baseline

Required before detection can work:

```bash
bash scripts/operations.sh baseline-create
```

What happens:
- SSH connects to Monitor VM
- Creates a network baseline snapshot
- Takes 2-3 minutes
- Shows success message when complete

Expected output:
```
Creating baseline snapshot...
✓ Baseline created successfully
```

---

### STEP 6: Start Detection

Open Terminal 1 and run:

```bash
bash scripts/operations.sh detection-start
```

What happens:
- Connects to Monitor VM
- Starts detection system
- Shows "Waiting for network events..."
- Listens for attacks in real-time

**KEEP THIS TERMINAL OPEN AND RUNNING**

---

### STEP 7: Run Attack

Open Terminal 2 (keep Terminal 1 running):

```bash
bash scripts/operations.sh attack-arp
```

What happens:
- Connects to Attacker VM
- Sends ARP spoofing packets
- Takes 10-15 seconds
- **Alerts appear in Terminal 1!**

---

### STEP 8: Watch Detection Response

In Terminal 1, you should see:

```
[DETECTION] ARP Spoofing detected
Source: 192.168.100.101
Target: 192.168.100.6
Severity: HIGH

[MITIGATION] Applying ARP response rate limiting
✓ Mitigation applied successfully
```

---

### STEP 9: View Results

Open Terminal 3:

```bash
bash scripts/operations.sh logs
```

This shows:
- All detected security events
- Timestamps
- Attack types
- Mitigation responses

---

## Complete Workflow Example

### Terminal 1 (Setup & Monitoring)

```bash
# Test network first
ping -c 1 192.168.100.8

# Run complete setup
bash scripts/quickstart.sh

# Wait for completion (~20 minutes)

# Create baseline
bash scripts/operations.sh baseline-create

# Start detection (leave running)
bash scripts/operations.sh detection-start
```

### Terminal 2 (Run Attacks)

```bash
# Wait for Terminal 1 to show "Waiting for network events..."

# Then run attack
bash scripts/operations.sh attack-arp

# Watch Terminal 1 for alerts!
```

### Terminal 3 (View Results)

```bash
# View detected events
bash scripts/operations.sh logs
```

---

## Quick Operation Commands

After setup is complete, use these:

```bash
# Interactive menu (recommended)
bash scripts/operations.sh

# OR use direct commands:
bash scripts/operations.sh connectivity       # Test VM reachability
bash scripts/operations.sh baseline-create    # Create baseline
bash scripts/operations.sh detection-start    # Start detection
bash scripts/operations.sh attack-arp         # Run ARP attack
bash scripts/operations.sh attack-mac         # Run MAC attack
bash scripts/operations.sh attack-dns         # Run DNS attack
bash scripts/operations.sh logs               # View security logs
bash scripts/operations.sh status             # Check Monitor VM
bash scripts/operations.sh ssh-monitor        # SSH to Monitor VM
bash scripts/operations.sh ssh-victim         # SSH to Victim VM
bash scripts/operations.sh ssh-attacker       # SSH to Attacker VM
```

---

## Troubleshooting During Execution

### Problem: "Cannot connect to Monitor VM"

**Solution:**
1. Check VMs are powered on
2. Run: `bash scripts/fix_network.sh`
3. Verify SSH works: `ssh monitor@192.168.100.8`

### Problem: "Operation timed out" during deployment

**Solution:**
1. Network issue detected
2. Run: `bash scripts/fix_network.sh`
3. Wait for network to stabilize
4. Run quickstart.sh again

### Problem: "ModuleNotFoundError: No module named scapy"

**Solution:**
- Option 1: `ssh monitor@192.168.100.8 "pip3 install scapy"`
- Option 2: `bash scripts/operations.sh deploy`

### Problem: Detection doesn't show alerts

**Solution:**
1. Verify baseline exists: `bash scripts/operations.sh baseline-check`
2. Check detection running: SSH to Monitor VM and check logs
3. Verify attack is running: `bash scripts/operations.sh attack-arp`

---

## Expected Timing

### First Time Setup

```
Network check:       ~1 minute
Project deployment:  ~3 minutes
VM setup scripts:    ~12 minutes
Dependency install:  ~3-4 minutes
─────────────────────────────
TOTAL:               ~20 minutes
```

### Subsequent Demo Runs

```
Create baseline:     ~2-3 minutes
Start detection:     ~1 minute
Run attack:          ~10-15 seconds
View results:        ~1 minute
─────────────────────────────
DEMO CYCLE:          ~5-10 minutes
```

---

## Key Points to Remember

1. **Network must work first**
   - `ping 192.168.100.8` must succeed
   - If not, run `bash scripts/fix_network.sh`

2. **Baseline is required**
   - Must run before detection
   - Only needs to be created once
   - Takes 2-3 minutes

3. **Keep detection running**
   - Open in dedicated terminal
   - Press Ctrl+C to stop
   - Can restart anytime

4. **Use multiple terminals**
   - Terminal 1: Detection (monitoring)
   - Terminal 2: Attacks (triggering)
   - Terminal 3: Results (viewing)

5. **All scripts are idempotent**
   - Safe to run multiple times
   - Previous configs detected
   - Safe to re-run after changes

---

## Need Help?

See quick reference:
```bash
bash scripts/QUICKREF.sh
```

Read detailed docs:
- `scripts/README.md` - Detailed documentation
- `SCRIPTS_SETUP_SUMMARY.md` - Complete overview
- `SETUP_HOME_LAB.md` - Lab architecture
- `AUTOMATED_SETUP_INDEX.md` - File index

---

## You're Ready! 🚀

Just follow the steps above and everything will work automatically!
