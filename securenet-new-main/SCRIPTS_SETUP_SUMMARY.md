# SecureNet Automated Setup - Complete Summary

## 🎯 Overview

You now have **6 fully automated setup scripts** that transform manual VM configuration from 30-45 minutes into a single-command workflow.

## 📦 What Was Created

### Main Orchestration Scripts
1. **quickstart.sh** (8.9 KB) - Master orchestration script
   - One command to deploy everything
   - Automates: network check → deployment → VM setup → dependency installation
   - **This is your primary entry point**

2. **fix_network.sh** (8.5 KB) - Network configuration helper
   - Detects hypervisor type automatically
   - Provides hypervisor-specific fix instructions
   - Tests connectivity before/after
   - Run this if `ping 192.168.100.8` fails

3. **deploy_to_vms.sh** (3.4 KB) - Project deployment
   - Transfers project files to all VMs via SSH
   - Used by quickstart.sh automatically
   - Can be run standalone to re-deploy code changes

### VM Setup Scripts
4. **setup_monitor_vm.sh** (7.3 KB)
   - Configures Ubuntu 22.04 for detection system
   - Installs Python, Scapy, tcpdump, libpcap
   - Sets up static IP: 192.168.100.8
   - Creates baselines directory and config files
   - Runs in ~5-7 minutes

5. **setup_victim_vm.sh** (4.9 KB)
   - Configures Ubuntu 22.04 as attack target
   - Installs web server (Apache) and DNS tools
   - Sets up static IP: 192.168.100.6
   - Enables IP forwarding for network simulation
   - Runs in ~3-5 minutes

6. **setup_attacker_vm.sh** (11 KB)
   - Configures Kali Linux for attack simulation
   - Installs attack tools: hping3, Scapy, dsniff, tcpdump
   - Creates attack scripts in ~/attack_scripts/:
     - `arp_spoof.py` - ARP spoofing
     - `mac_flood.py` - MAC flooding
     - `dns_spoof.py` - DNS spoofing
   - Runs in ~4-6 minutes

### Helper & Documentation
7. **operations.sh** (9.2 KB)
   - Post-setup operations helper
   - Create baseline, start detection, run attacks
   - Check status, view logs, SSH access
   - Interactive menu or command-line interface

8. **scripts/README.md** (Comprehensive documentation)
   - Detailed script descriptions
   - Usage examples for each script
   - Network configuration details
   - Troubleshooting guide

## 🚀 Quick Start (3 Steps)

### Step 1: Fix Network (If Needed)
```bash
bash scripts/fix_network.sh
```
Only needed if you get "Request timeout" when pinging VMs.

### Step 2: Run Complete Setup
```bash
bash scripts/quickstart.sh
```
This does everything:
- Checks network connectivity
- Deploys code to all 3 VMs
- Runs setup scripts automatically
- Installs Python dependencies

**Duration:** 15-20 minutes (first run)

### Step 3: Use Operations Helper
```bash
bash scripts/operations.sh
```
Interactive menu for:
- Creating baselines
- Starting detection
- Running attacks
- Checking status
- SSH access to VMs

## 📊 Script Workflow

```
quickstart.sh
├─→ check network connectivity
├─→ detect hypervisor
├─→ deploy_to_vms.sh
│   ├─→ tar project files
│   ├─→ SSH to Monitor VM → extract
│   ├─→ SSH to Victim VM → extract
│   └─→ SSH to Attacker VM → extract
├─→ run setup_monitor_vm.sh (remotely)
│   └─→ install detection system dependencies
├─→ run setup_victim_vm.sh (remotely)
│   └─→ install web server & network tools
├─→ run setup_attacker_vm.sh (remotely)
│   └─→ install attack tools & create scripts
├─→ pip install on all VMs
└─→ display next steps
```

## 🔧 Network Configuration

### Current Setup
```
macOS Host (192.168.137.x WiFi)
└── bridge100 Host-Only Network (192.168.100.0/24)
    ├── Monitor VM: 192.168.100.8 (Ubuntu)
    ├── Victim VM: 192.168.100.6 (Ubuntu)
    └── Attacker VM: 192.168.100.101 (Kali)
```

### Key Points
- All VMs on isolated Host-Only network (no internet leakage)
- Each VM has static IP configured
- macOS host acts as gateway/monitoring point
- No bridge networking needed

### If Network Doesn't Work
```bash
# Run the network fix script
bash scripts/fix_network.sh

# This will:
# 1. Detect your hypervisor (Parallels/VMware/VirtualBox/UTM)
# 2. Provide specific instructions for that hypervisor
# 3. Test connectivity after you apply the fix
```

## 💡 Common Operations

### Create Baseline (after Monitor setup)
```bash
bash scripts/operations.sh baseline-create
```

### Start Detection
```bash
bash scripts/operations.sh detection-start
```

### Run ARP Spoof Attack
```bash
bash scripts/operations.sh attack-arp
```

### SSH to Attacker VM
```bash
bash scripts/operations.sh ssh-attacker
# or manually:
ssh attacker@192.168.100.101
cd ~/securenet
sudo python3 scripts/attack_scripts/arp_spoof.py
```

### View Security Logs
```bash
bash scripts/operations.sh logs
```

### Re-deploy Code Changes
```bash
bash scripts/operations.sh deploy
```

## ⚙️ Script Features

✅ **Error Handling**
- All scripts use `set -e` (exit on any error)
- Clear error messages with next steps
- Network connectivity verified before operations

✅ **User Feedback**
- Color-coded output (Green ✓, Red ✗, Yellow ⚠, Blue info)
- Progress indicators at each step
- Duration estimates provided
- Step-by-step numbered progress

✅ **Idempotency**
- Scripts can be run multiple times
- Previous configurations detected
- Safe to re-run after changes

✅ **Cross-Platform**
- Works on Parallels, VMware, VirtualBox, UTM
- macOS 10.15+ compatible
- SSH-based (no hypervisor-specific APIs needed)

## 📋 Typical Execution Flow

### First Time (Complete Fresh Setup)
```bash
# 1. Ensure all 3 VMs are powered on

# 2. Fix network if needed
bash scripts/fix_network.sh

# 3. Run complete orchestration
bash scripts/quickstart.sh
# This takes ~20 minutes and sets everything up

# 4. Create baseline
bash scripts/operations.sh baseline-create

# 5. Start detection
bash scripts/operations.sh detection-start
# Keep this running in a terminal

# 6. In another terminal, run attack
bash scripts/operations.sh attack-arp
```

### After Making Code Changes
```bash
# 1. Make your code changes on macOS

# 2. Re-deploy to VMs
bash scripts/operations.sh deploy

# 3. Restart detection (if running)
# Press Ctrl+C on detection terminal
# bash scripts/operations.sh detection-start
```

### Testing Different Attacks
```bash
bash scripts/operations.sh attack-arp
bash scripts/operations.sh attack-mac
bash scripts/operations.sh attack-dns
```

## 🐛 Troubleshooting

### Problem: "Cannot connect to Monitor VM"
```bash
# Check network first
bash scripts/fix_network.sh

# Verify VM is running in hypervisor
# Check SSH: ssh monitor@192.168.100.8 "exit"
```

### Problem: "Permission denied" errors
```bash
# Make scripts executable
chmod +x scripts/*.sh

# Then run again
bash scripts/quickstart.sh
```

### Problem: Project files not on VM
```bash
# Re-deploy
bash scripts/deploy_to_vms.sh

# Verify
ssh monitor@192.168.100.8 "ls ~/securenet"
```

### Problem: VMs can SSH but ping fails
```bash
# Classic network subnet mismatch
bash scripts/fix_network.sh
# Follow instructions to reconfigure hypervisor
```

## 📈 What Each Script Installs

### Monitor VM (Ubuntu 22.04)
- Python 3.8+
- Scapy (packet crafting)
- tcpdump & libpcap (packet capture)
- pip packages: scapy, psutil, fastapi, uvicorn
- SecureNet project code
- Configuration files

### Victim VM (Ubuntu 22.04)
- Apache web server
- DNS tools (dnsmasq, nslookup)
- Network tools (iptables, iproute2)
- IP forwarding enabled
- SecureNet project code

### Attacker VM (Kali Linux)
- hping3 (ICMP/TCP/UDP flood)
- Scapy (custom packet crafting)
- dsniff (network analysis)
- tcpdump (packet capture)
- Attack scripts (arp_spoof.py, mac_flood.py, dns_spoof.py)
- SecureNet project code

## 🎯 Next Steps After Setup

1. **Verify everything works:**
   ```bash
   bash scripts/operations.sh connectivity
   ```

2. **Create baseline:**
   ```bash
   bash scripts/operations.sh baseline-create
   ```

3. **Start detection:**
   ```bash
   bash scripts/operations.sh detection-start
   ```

4. **In new terminal, run attack:**
   ```bash
   bash scripts/operations.sh attack-arp
   ```

5. **Watch detection system respond** in original terminal

6. **View results:**
   ```bash
   bash scripts/operations.sh logs
   ```

## 📚 Documentation Files

- `scripts/README.md` - Detailed script documentation
- `SETUP_HOME_LAB.md` - Complete lab architecture guide
- `PRODUCTION_DEPLOYMENT_SUMMARY.md` - Production considerations
- `ENHANCEMENT_SUMMARY.md` - Architecture improvements
- `README.md` - Main project documentation

## 🎓 Hackathon Presentation

### Demo Flow
1. Show network architecture (3 VMs on host-only bridge)
2. Start detection: `bash scripts/operations.sh detection-start`
3. Run attack: `bash scripts/operations.sh attack-arp`
4. Show detection in action (security events in logs)
5. Show mitigation response (ARP tables updated)
6. Explain behavior-based detection advantages
7. Discuss use cases (enterprise LAN, lab networks)

### Time Requirements
- Complete setup: 20 minutes (one time)
- Each demo run: 5 minutes (baseline + attack + mitigation)
- Total presentation: 10-15 minutes with explanation

## 🔐 Security Considerations

✅ **Isolated Network**
- Host-only networking keeps attacks contained
- No internet bridge possible
- Lab environment only (not for production)

✅ **Safe Attack Tools**
- All attacks run within controlled lab network
- Limited to Host-Only subnet (192.168.100.0/24)
- Can't affect external systems

✅ **Reversible Mitigations**
- All changes logged and reversible
- Baseline snapshots stored
- System can return to original state

## 📞 Support

If scripts fail:
1. Check all 3 VMs are running
2. Verify network: `bash scripts/fix_network.sh`
3. Check SSH access: `ssh monitor@192.168.100.8 "exit"`
4. Check logs: Look in VM `/var/log/syslog`
5. Re-run quickstart: `bash scripts/quickstart.sh`

---

**Setup Time Saved:** ~30-45 minutes per VM (3 VMs = ~1.5-2 hours)
**Automated by These Scripts:** 20 minutes total setup

**Created:** January 2025
**Compatible:** Ubuntu 22.04, Kali Linux, macOS 10.15+
