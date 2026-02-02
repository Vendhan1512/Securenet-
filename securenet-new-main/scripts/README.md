# SecureNet Deployment Scripts

This directory contains automated scripts to deploy and configure the SecureNet LAN Security System across multiple VMs.

## 📋 Script Overview

### 1. **quickstart.sh** - Recommended Starting Point ⭐
The orchestration master script that automates the entire setup process.

**Usage:**
```bash
bash quickstart.sh
```

**What it does:**
- Verifies network connectivity to all VMs
- Deploys the project to Monitor, Victim, and Attacker VMs
- Runs VM setup scripts automatically
- Installs project dependencies
- Provides next steps for running detection

**Duration:** ~15-20 minutes (first run)

**Prerequisites:**
- All three VMs (Monitor, Victim, Attacker) must be running
- VMs must be reachable at their configured IPs
- macOS host must have SSH access to VMs

---

### 2. **fix_network.sh** - Network Configuration
Diagnoses and guides fixing host-only network subnet mismatches.

**Usage:**
```bash
bash fix_network.sh
```

**What it does:**
- Detects current network configuration
- Auto-identifies hypervisor type (Parallels/VMware/VirtualBox/UTM)
- Provides hypervisor-specific instructions to fix 192.168.100.x subnet
- Tests connectivity after configuration

**When to use:**
- Before running `quickstart.sh` if `ping 192.168.100.8` fails from macOS
- When VMs are not reachable from the host

**Duration:** ~5 minutes (plus manual hypervisor config)

---

### 3. **setup_monitor_vm.sh** - Monitor VM Setup
Configures the Detection System VM (Ubuntu 22.04).

**Usage (automatic via quickstart.sh):**
```bash
bash quickstart.sh
```

**Manual usage:**
```bash
ssh monitor@192.168.100.8 'bash -s' < setup_monitor_vm.sh
```

**What it does (10 steps):**
1. System update and upgrade
2. Hostname configuration (monitor-security)
3. Static IP configuration (192.168.100.8/24)
4. Dependencies installation
5. Python packages setup
6. Project directory creation
7. Configuration file generation
8. tcpdump permissions setup
9. Baseline directory initialization
10. Verification checks

**Duration:** ~5-7 minutes

**Output:**
- Configured detection system
- Ready to create baseline and run detection

---

### 4. **setup_victim_vm.sh** - Victim VM Setup
Configures the test target VM (Ubuntu 22.04).

**Usage (automatic via quickstart.sh):**
```bash
bash quickstart.sh
```

**Manual usage:**
```bash
ssh victim@192.168.100.6 'bash -s' < setup_victim_vm.sh
```

**What it does (8 steps):**
1. System update and upgrade
2. Hostname configuration (victim-host)
3. Static IP configuration (192.168.100.6/24)
4. Network tools installation
5. DNS resolver setup
6. HTTP server deployment (Apache)
7. IP forwarding and routing
8. Connectivity verification

**Duration:** ~3-5 minutes

**Output:**
- Configured victim/target host
- Running Apache web server
- DNS resolver active

---

### 5. **setup_attacker_vm.sh** - Attacker VM Setup
Configures the attack simulation VM (Kali Linux).

**Usage (automatic via quickstart.sh):**
```bash
bash quickstart.sh
```

**Manual usage:**
```bash
ssh attacker@192.168.100.101 'bash -s' < setup_attacker_vm.sh
```

**What it does (8 steps):**
1. System update and upgrade
2. Hostname configuration (attacker-kali)
3. Static IP configuration (192.168.100.101/24)
4. Attack tools installation (hping3, Scapy, dsniff, tcpdump)
5. Python attack libraries (Scapy, netaddr)
6. Attack scripts directory creation
7. Pre-built attack scripts deployment:
   - `arp_spoof.py` - ARP spoofing attacks
   - `mac_flood.py` - MAC flooding attacks
   - `dns_spoof.py` - DNS spoofing attacks
8. Connectivity verification

**Duration:** ~4-6 minutes

**Output:**
- Configured attack platform
- Ready-to-use attack scripts in `~/attack_scripts/`

---

### 6. **deploy_to_vms.sh** - Manual Project Deployment
Deploys the SecureNet project files to VMs.

**Usage (automatic via quickstart.sh):**
```bash
bash quickstart.sh
```

**Manual usage:**
```bash
bash deploy_to_vms.sh [monitor-ip] [victim-ip] [attacker-ip]

# Examples:
bash deploy_to_vms.sh  # Uses defaults
bash deploy_to_vms.sh 192.168.100.8 192.168.100.6 192.168.100.101
```

**What it does:**
- Compresses project files (excludes venv, __pycache__, logs)
- Transfers via SSH to each VM
- Extracts and sets permissions

**When to use:**
- After fixing network issues
- To re-deploy with code changes
- If VMs lost project files

**Duration:** ~2-3 minutes (depending on network)

---

## 🚀 Quick Start Workflow

### First Time Setup
```bash
# 1. Fix network if needed
bash fix_network.sh

# 2. Run complete orchestration
bash quickstart.sh

# 3. Follow on-screen next steps
```

### After Changes to Code
```bash
# Re-deploy and reinstall
bash deploy_to_vms.sh
ssh monitor@192.168.100.8 "cd ~/securenet && pip3 install -q -e ."
```

### Manual VM Setup
```bash
# If you need to manually configure a VM
ssh monitor@192.168.100.8 'bash -s' < setup_monitor_vm.sh
ssh victim@192.168.100.6 'bash -s' < setup_victim_vm.sh
ssh attacker@192.168.100.101 'bash -s' < setup_attacker_vm.sh
```

---

## 🔍 Network Configuration

### Expected Network Layout
```
macOS Host
├── en0: 192.168.137.190 (WiFi)
└── bridge100: 192.168.100.1 (Host-Only Bridge)
    ├── Monitor VM: 192.168.100.8
    ├── Victim VM: 192.168.100.6
    └── Attacker VM: 192.168.100.101
```

### Testing Connectivity
```bash
# From macOS
ping 192.168.100.8   # Should work
ssh monitor@192.168.100.8   # Should work

# From Monitor VM
ping 192.168.100.1   # Gateway
ping 192.168.100.6   # Victim
ping 192.168.100.101 # Attacker
```

### Troubleshooting Network Issues

**Problem: "Request timeout" when pinging from macOS**
```bash
# Solution: Run network fix script
bash fix_network.sh
```

**Problem: VMs can't reach each other**
```bash
# Check VM has correct IP
ssh monitor@192.168.100.8 "ip addr | grep 192.168.100"

# Check routing
ssh monitor@192.168.100.8 "ip route"

# Should show:
# 192.168.100.0/24 dev eth0 proto kernel scope link src 192.168.100.8
```

**Problem: SSH works but ping doesn't**
```bash
# Hypervisor bridge is on wrong subnet
# Run: bash fix_network.sh
# Then restart VMs
```

---

## 📊 Script Dependencies

| Script | Requires | Installed By |
|--------|----------|--------------|
| quickstart.sh | All below | - |
| fix_network.sh | macOS CLI tools | Built-in |
| deploy_to_vms.sh | SSH to VMs | quickstart.sh |
| setup_monitor_vm.sh | Ubuntu 22.04 | quickstart.sh |
| setup_victim_vm.sh | Ubuntu 22.04 | quickstart.sh |
| setup_attacker_vm.sh | Kali Linux | quickstart.sh |

---

## 🛠️ Running Individual Setup Steps

### Create Baseline (after Monitor setup)
```bash
ssh monitor@192.168.100.8
cd ~/securenet
python3 -m lan_security_system.baseline create --interface enp0s1
```

### Start Detection (after baseline)
```bash
ssh monitor@192.168.100.8
cd ~/securenet
python3 production_main.py --interface enp0s1
```

### Run Attack (from Attacker VM)
```bash
ssh attacker@192.168.100.101
cd ~/securenet
sudo python3 scripts/attack_scripts/arp_spoof.py
```

---

## 📝 Script Features

### Error Handling
- All scripts use `set -e` (exit on error)
- Network connectivity verified before operations
- Clear error messages with next steps

### Progress Indication
- Color-coded output (Green ✓, Red ✗, Yellow ⚠, Blue info)
- Step-by-step progress indicators
- Duration estimates provided

### Idempotency
- Scripts can be run multiple times safely
- Previous configurations detected
- Incremental updates applied

### Logging
- All operations logged to console
- Clear success/failure indicators
- Verification checks at each step

---

## 🔐 Security Notes

- Scripts require SSH key access to VMs
- No hardcoded passwords
- Attack scripts prompt for `sudo` when needed
- Baseline configurations stored securely

---

## 📞 Troubleshooting

### Common Issues

**"Permission denied" when running scripts**
```bash
chmod +x scripts/*.sh
bash scripts/quickstart.sh
```

**"Cannot connect to VM"**
```bash
# Check VM is running in hypervisor
# Check SSH is enabled: ssh monitor@192.168.100.8 "exit"
# Check network: bash scripts/fix_network.sh
```

**"Network unreachable" errors**
```bash
# This is expected until network is fixed
bash scripts/fix_network.sh
# Then: restart VMs
# Then: bash scripts/quickstart.sh
```

**Script runs but VMs don't have project files**
```bash
# Re-deploy manually
bash scripts/deploy_to_vms.sh
```

---

## 📚 Related Documentation

- [SETUP_HOME_LAB.md](../SETUP_HOME_LAB.md) - Lab architecture and manual setup
- [PRODUCTION_DEPLOYMENT_SUMMARY.md](../PRODUCTION_DEPLOYMENT_SUMMARY.md) - Production considerations
- [README.md](../README.md) - Main project documentation

---

## 💡 Tips

1. **Run on clean VMs** - Easiest if starting fresh
2. **Keep scripts in sync** - Re-download if project updates
3. **Test network first** - Use `fix_network.sh` before `quickstart.sh`
4. **Monitor logs** - Check `/var/log/syslog` on VMs for issues
5. **Create baseline early** - Needed before running detection

---

**Last Updated:** January 2025
**Compatible With:** Ubuntu 22.04 (Monitor/Victim), Kali Linux (Attacker)
**Hypervisors:** Parallels, VMware Fusion, VirtualBox, UTM
