#!/bin/bash
# Quick Reference - SecureNet Automated Setup
# Display this guide with: bash scripts/QUICKREF.sh

cat << 'EOF'

╔══════════════════════════════════════════════════════════════════════════════╗
║                    SecureNet Automated Setup Quick Reference                ║
║                            One-Line Command Guide                            ║
╚══════════════════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════════════════════
🚀 GETTING STARTED (Do This First)
═══════════════════════════════════════════════════════════════════════════════

1️⃣  FIX NETWORK (if needed)
    bash scripts/fix_network.sh
    └─ Use this if: ping 192.168.100.8 times out
    └─ Detects hypervisor & provides fix instructions
    └─ Time: 5 minutes (plus manual hypervisor config)

2️⃣  COMPLETE SETUP (All-in-One)
    bash scripts/quickstart.sh
    └─ Deploys to all 3 VMs
    └─ Runs setup automatically
    └─ Installs dependencies
    └─ Time: 20 minutes
    └─ Result: Everything ready to use

═══════════════════════════════════════════════════════════════════════════════
🎮 AFTER SETUP (Common Operations)
═══════════════════════════════════════════════════════════════════════════════

🔌 DETECTION SYSTEM (Monitor VM)
    bash scripts/operations.sh baseline-create
    └─ Creates network baseline (run once before detection)

    bash scripts/operations.sh detection-start
    └─ Starts detection system
    └─ Shows attacks in real-time
    └─ Run in its own terminal (Ctrl+C to stop)

💣 ATTACK SIMULATION (Attacker VM)
    bash scripts/operations.sh attack-arp
    └─ Runs ARP spoofing attack
    └─ Target: 192.168.100.6 (Victim)
    └─ Run in separate terminal while detection is running

    bash scripts/operations.sh attack-mac
    └─ Runs MAC flooding attack

    bash scripts/operations.sh attack-dns
    └─ Runs DNS spoofing attack

📊 SYSTEM STATUS
    bash scripts/operations.sh connectivity
    └─ Check if all VMs are reachable

    bash scripts/operations.sh status
    └─ Monitor VM system info & baseline status

    bash scripts/operations.sh logs
    └─ View detected security events

🔄 SSH ACCESS
    bash scripts/operations.sh ssh-monitor
    bash scripts/operations.sh ssh-victim
    bash scripts/operations.sh ssh-attacker
    └─ Direct SSH access to any VM

═══════════════════════════════════════════════════════════════════════════════
📡 NETWORK QUICK REFERENCE
═══════════════════════════════════════════════════════════════════════════════

Host-Only Network: 192.168.100.0/24

  🖥️  Monitor VM    (Detection System)    192.168.100.8     ubuntu
  🎯 Victim VM      (Attack Target)       192.168.100.6     ubuntu
  ⚔️  Attacker VM    (Attack Source)       192.168.100.101   kali

Test Connectivity:
  ping 192.168.100.8
  ssh monitor@192.168.100.8

═══════════════════════════════════════════════════════════════════════════════
🔧 MANUAL OPERATIONS (Without Interactive Menu)
═══════════════════════════════════════════════════════════════════════════════

Create Baseline:
  ssh monitor@192.168.100.8
  cd ~/securenet
  python3 -m lan_security_system.baseline create --interface enp0s1

Start Detection:
  ssh monitor@192.168.100.8
  cd ~/securenet
  python3 production_main.py --interface enp0s1

Run Attack (on Attacker VM):
  ssh attacker@192.168.100.101
  cd ~/securenet
  sudo python3 scripts/attack_scripts/arp_spoof.py

View Logs:
  ssh monitor@192.168.100.8
  tail -f ~/securenet/logs/security_events.jsonl

═══════════════════════════════════════════════════════════════════════════════
💻 SCRIPT FILES (What Each Does)
═══════════════════════════════════════════════════════════════════════════════

quickstart.sh
  ├─ Master orchestration script
  ├─ Checks network connectivity
  ├─ Deploys to all 3 VMs
  ├─ Runs setup scripts automatically
  └─ Time: 20 minutes total
  └─ USE THIS FIRST!

fix_network.sh
  ├─ Diagnoses network problems
  ├─ Auto-detects hypervisor type
  ├─ Provides hypervisor-specific fix
  └─ Time: 5 minutes

deploy_to_vms.sh
  ├─ Transfers project files to VMs
  ├─ Used by quickstart.sh automatically
  └─ Can re-deploy code changes manually

setup_monitor_vm.sh
  ├─ Configures Monitor VM (Ubuntu)
  ├─ Installs detection system dependencies
  └─ Runs automatically by quickstart.sh

setup_victim_vm.sh
  ├─ Configures Victim VM (Ubuntu)
  ├─ Installs web server & network tools
  └─ Runs automatically by quickstart.sh

setup_attacker_vm.sh
  ├─ Configures Attacker VM (Kali Linux)
  ├─ Installs attack tools & creates scripts
  └─ Runs automatically by quickstart.sh

operations.sh
  ├─ Helper for post-setup operations
  ├─ Create baseline, start detection
  ├─ Run attacks, check status, view logs
  └─ Run without arguments for interactive menu

═══════════════════════════════════════════════════════════════════════════════
⚡ QUICK DEMO WORKFLOW (10 Minutes)
═══════════════════════════════════════════════════════════════════════════════

Terminal 1 (Monitor VM):
  $ bash scripts/operations.sh baseline-create
  [waiting for baseline to complete...]
  
  $ bash scripts/operations.sh detection-start
  [system waiting for attacks...]

Terminal 2 (Attacker VM):
  $ bash scripts/operations.sh attack-arp
  [sending ARP packets...]

Watch Terminal 1 for detection alerts! 🚨

═══════════════════════════════════════════════════════════════════════════════
❓ COMMON ISSUES & FIXES
═══════════════════════════════════════════════════════════════════════════════

❌ "ping 192.168.100.8: Request timeout"
   ✓ Run: bash scripts/fix_network.sh

❌ "Permission denied" when running scripts
   ✓ Run: chmod +x scripts/*.sh

❌ "Cannot connect to Monitor VM"
   ✓ Check: All 3 VMs running in hypervisor
   ✓ Check: Network connectivity (bash scripts/fix_network.sh)

❌ "Project files not on VM"
   ✓ Run: bash scripts/deploy_to_vms.sh

❌ "ModuleNotFoundError: No module named 'scapy'"
   ✓ Run: ssh monitor@192.168.100.8 "pip3 install scapy"

❌ "No baseline created"
   ✓ Run: bash scripts/operations.sh baseline-create

═══════════════════════════════════════════════════════════════════════════════
📚 DOCUMENTATION
═══════════════════════════════════════════════════════════════════════════════

scripts/README.md
  └─ Detailed script documentation

SCRIPTS_SETUP_SUMMARY.md
  └─ Complete overview of automation

SETUP_HOME_LAB.md
  └─ Lab architecture & manual setup (for reference)

PRODUCTION_DEPLOYMENT_SUMMARY.md
  └─ Production deployment strategy

ENHANCEMENT_SUMMARY.md
  └─ Architecture improvements

README.md
  └─ Main project documentation

═══════════════════════════════════════════════════════════════════════════════
🎯 TYPICAL WORKFLOW
═══════════════════════════════════════════════════════════════════════════════

1. Power on all 3 VMs (in hypervisor)

2. Fix network if needed:
   bash scripts/fix_network.sh

3. Run complete setup:
   bash scripts/quickstart.sh
   [This takes ~20 minutes]

4. Create baseline:
   bash scripts/operations.sh baseline-create

5. Start detection:
   bash scripts/operations.sh detection-start

6. In new terminal, run attack:
   bash scripts/operations.sh attack-arp

7. Watch Terminal 1 for detection alerts

8. View results:
   bash scripts/operations.sh logs

═══════════════════════════════════════════════════════════════════════════════
🚀 YOU'RE READY!
═══════════════════════════════════════════════════════════════════════════════

Just run:
  bash scripts/quickstart.sh

Then enjoy automated setup! ✨

═══════════════════════════════════════════════════════════════════════════════

EOF

# Make this script executable
chmod +x "$(dirname "$0")/QUICKREF.sh" 2>/dev/null || true
