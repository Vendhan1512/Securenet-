#!/bin/bash
# SecureNet Attack Testing Script
# Run various attacks from Attacker VM and monitor detection

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
echo -e "${BLUE}SecureNet Attack Testing${NC}"
echo -e "${BLUE}════════════════════════════════════════${NC}"
echo ""

# Test 1: Port Scan Detection
echo -e "${YELLOW}[Test 1] Port Scan Detection${NC}"
echo "Running nmap scan from Attacker VM to Victim..."
sshpass -p "$VM_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $ATTACKER_USER@$ATTACKER_IP "
    timeout 10 nmap -sS $VICTIM_IP 2>/dev/null || echo 'Scan attempt completed'
" 2>/dev/null
echo -e "${GREEN}✓ Port scan attack executed${NC}"
echo ""

sleep 2

# Test 2: Ping Flood (DoS Attack)
echo -e "${YELLOW}[Test 2] Ping Flood (DoS) Detection${NC}"
echo "Sending ping flood from Attacker to Victim (3 seconds)..."
sshpass -p "$VM_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $ATTACKER_USER@$ATTACKER_IP "
    timeout 3 ping -f $VICTIM_IP >/dev/null 2>&1 || echo 'Flood completed'
" 2>/dev/null
echo -e "${GREEN}✓ Ping flood attack executed${NC}"
echo ""

sleep 2

# Test 3: SYN Flood (hping3)
echo -e "${YELLOW}[Test 3] SYN Flood Detection${NC}"
echo "Sending SYN flood to Victim port 80 (3 seconds)..."
sshpass -p "$VM_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $ATTACKER_USER@$ATTACKER_IP "
    timeout 3 sudo hping3 -S --flood $VICTIM_IP -p 80 2>/dev/null || echo 'SYN flood completed'
" 2>/dev/null
echo -e "${GREEN}✓ SYN flood attack executed${NC}"
echo ""

sleep 2

# Test 4: Connection Attempt
echo -e "${YELLOW}[Test 4] Connection Attempt Detection${NC}"
echo "Attempting SSH connection from Attacker to Victim..."
sshpass -p "$VM_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $ATTACKER_USER@$ATTACKER_IP "
    timeout 3 ssh -o ConnectTimeout=2 root@$VICTIM_IP 'exit' 2>/dev/null || echo 'Connection attempt completed'
" 2>/dev/null
echo -e "${GREEN}✓ Connection attempt executed${NC}"
echo ""

# Check Monitor VM Logs
echo -e "${BLUE}════════════════════════════════════════${NC}"
echo -e "${YELLOW}Checking Monitor VM for detected attacks...${NC}"
echo -e "${BLUE}════════════════════════════════════════${NC}"
echo ""

sshpass -p "$VM_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $MONITOR_USER@$MONITOR_IP "
    cd ~/securenet
    
    echo '📊 Recent Security Events:'
    if [ -f logs/security_events.jsonl ]; then
        tail -10 logs/security_events.jsonl | python3 -m json.tool 2>/dev/null | head -50 || tail -3 logs/security_events.jsonl
    else
        echo 'No security events logged yet'
    fi
    
    echo ''
    echo '🚨 Mitigation Actions:'
    if [ -f logs/mitigation_actions.jsonl ]; then
        tail -5 logs/mitigation_actions.jsonl | python3 -m json.tool 2>/dev/null | head -30 || tail -3 logs/mitigation_actions.jsonl
    else
        echo 'No mitigation actions logged yet'
    fi
" 2>/dev/null

echo ""
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ Attack Testing Complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""
echo "To view real-time detection logs:"
echo "  sshpass -p achu2006 ssh monitor@192.168.128.8 'tail -f ~/securenet/logs/security_events.jsonl'"
echo ""
echo "To run more sophisticated tests:"
echo "  bash scripts/test_attacks.sh"
