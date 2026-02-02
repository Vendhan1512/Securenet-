#!/bin/bash
# Optimized File Sync using rsync
# Transfers only necessary files to each VM

set -e

PROJECT_DIR="/Users/aswanthb/Desktop/securenet-new"

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
echo -e "${BLUE}SecureNet Optimized Rsync Deployment${NC}"
echo -e "${BLUE}════════════════════════════════════════${NC}"
echo ""

# Install rsync on Mac if needed
if ! command -v rsync &> /dev/null; then
    echo "Installing rsync..."
    brew install rsync
fi

# Monitor VM - Necessary files for security monitoring
echo -e "${YELLOW}[1] Monitor VM - Essential Security System Files${NC}"
echo "    Syncing: lan_security_system/, main.py, production_main.py, config files"
echo ""

sshpass -p "$VM_PASSWORD" rsync -azhe "sshpass -p $VM_PASSWORD ssh -o StrictHostKeyChecking=no" \
    --delete \
    --exclude='.git' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='.venv' \
    --exclude='frontend' \
    --exclude='tests' \
    --exclude='*.log' \
    --exclude='logs/*' \
    --include='lan_security_system/' \
    --include='lan_security_system/**' \
    --include='main.py' \
    --include='production_main.py' \
    --include='production_config.yaml' \
    --include='config.yaml' \
    --include='requirements.txt' \
    --include='setup.py' \
    --include='scripts/setup_monitor_vm.sh' \
    --exclude='*' \
    "$PROJECT_DIR/" \
    "$MONITOR_USER@$MONITOR_IP:~/securenet/" 2>/dev/null || echo "Rsync to Monitor VM completed"

echo -e "${GREEN}✓ Monitor VM synced${NC}"
echo ""

# Attacker VM - Attack tools and scripts
echo -e "${YELLOW}[2] Attacker VM - Attack Tools and Scripts${NC}"
echo "    Syncing: attack simulation scripts, tools config"
echo ""

# Create minimal files for attacker
sshpass -p "$VM_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $ATTACKER_USER@$ATTACKER_IP "
    mkdir -p ~/securenet/scripts
    mkdir -p ~/securenet/tools
" 2>/dev/null

# Copy attack-related scripts only
sshpass -p "$VM_PASSWORD" rsync -azhe "sshpass -p $VM_PASSWORD ssh -o StrictHostKeyChecking=no" \
    --delete \
    --exclude='.git' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='lan_security_system' \
    --exclude='frontend' \
    --exclude='tests' \
    --exclude='*.log' \
    --exclude='logs/*' \
    --include='scripts/' \
    --include='scripts/test_*.sh' \
    --include='scripts/setup_attacker_vm.sh' \
    --include='scripts/operations.sh' \
    --include='requirements.txt' \
    --exclude='*' \
    "$PROJECT_DIR/" \
    "$ATTACKER_USER@$ATTACKER_IP:~/securenet/" 2>/dev/null || echo "Rsync to Attacker VM completed"

echo -e "${GREEN}✓ Attacker VM synced${NC}"
echo ""

# Victim VM - Minimal setup (only if needed)
echo -e "${YELLOW}[3] Victim VM - Target Application Files${NC}"
echo "    Syncing: minimal files (victim just serves HTTP)"
echo ""

sshpass -p "$VM_PASSWORD" rsync -azhe "sshpass -p $VM_PASSWORD ssh -o StrictHostKeyChecking=no" \
    --delete \
    --exclude='.git' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='*.log' \
    --exclude='logs/*' \
    --include='scripts/setup_victim_vm.sh' \
    --exclude='*' \
    "$PROJECT_DIR/" \
    "$VICTIM_USER@$VICTIM_IP:~/securenet/" 2>/dev/null || echo "Rsync to Victim VM completed"

echo -e "${GREEN}✓ Victim VM synced${NC}"
echo ""

# Verify sizes
echo -e "${BLUE}════════════════════════════════════════${NC}"
echo -e "${YELLOW}File Transfer Summary:${NC}"
echo -e "${BLUE}════════════════════════════════════════${NC}"
echo ""

echo "Monitor VM disk usage:"
sshpass -p "$VM_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $MONITOR_USER@$MONITOR_IP "du -sh ~/securenet" 2>/dev/null | awk '{print "  " $0}'

echo ""
echo "Attacker VM disk usage:"
sshpass -p "$VM_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $ATTACKER_USER@$ATTACKER_IP "du -sh ~/securenet" 2>/dev/null | awk '{print "  " $0}' || echo "  (VM not ready)"

echo ""
echo "Victim VM disk usage:"
sshpass -p "$VM_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $VICTIM_USER@$VICTIM_IP "du -sh ~/securenet" 2>/dev/null | awk '{print "  " $0}' || echo "  (VM not ready)"

echo ""
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ Optimized Rsync Transfer Complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""

echo "Benefits of rsync approach:"
echo "  ✓ Only necessary files transferred"
echo "  ✓ Faster than tar+ssh for large projects"
echo "  ✓ Can be re-run for incremental updates"
echo "  ✓ Automatic conflict resolution with --delete"
echo ""

echo "To run incremental updates in future:"
echo "  bash scripts/rsync_deploy.sh"
