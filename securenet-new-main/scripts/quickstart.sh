#!/bin/bash
# SecureNet Quick Start Script
# Orchestrates the entire setup process from macOS
# Usage: bash quickstart.sh

set -e

echo "╔════════════════════════════════════════════════════════╗"
echo "║     SecureNet Quick Start Orchestration Script         ║"
echo "║  Automated setup from your macOS host - All VMs        ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# Configuration
PROJECT_DIR="/Users/aswanthb/Desktop/securenet-new"
MONITOR_IP="192.168.128.8"
VICTIM_IP="192.168.128.6"
ATTACKER_IP="192.168.128.101"

# VM Credentials
MONITOR_USER="monitor"
VICTIM_USER="achu2"
ATTACKER_USER="achu"
VM_PASSWORD="achu2006"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# =============================================================================
# PHASE 1: Network Verification
# =============================================================================
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}PHASE 1: Network Verification${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo ""

echo "Checking hypervisor host-only network configuration..."
echo ""

BRIDGE_IP=$(ifconfig | grep -B1 "inet 192.168.128" | grep inet | awk '{print $2}' || true)

if [ -z "$BRIDGE_IP" ]; then
    echo -e "${RED}✗ No host-only bridge found on 192.168.128.x${NC}"
    echo ""
    echo -e "${YELLOW}To fix the network, run:${NC}"
    echo "  bash scripts/fix_network.sh"
    echo ""
    echo "This script will guide you through configuring your hypervisor."
    echo ""
    read -p "Run network fix now? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        bash scripts/fix_network.sh
        exit 0
    else
        exit 1
    fi
else
    echo -e "${GREEN}✓ Host-only bridge detected: $BRIDGE_IP${NC}"
fi

echo ""
echo "Testing connectivity to VMs..."
echo ""

# Test Monitor VM
echo -n "  Monitor VM (192.168.128.8):  "
if ping -c 1 -W 2 $MONITOR_IP > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Reachable${NC}"
else
    echo -e "${RED}✗ Not reachable${NC}"
    echo "  Make sure Monitor VM is running"
fi

# Test Victim VM
echo -n "  Victim VM (192.168.128.6):   "
if ping -c 1 -W 2 $VICTIM_IP > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Reachable${NC}"
else
    echo -e "${RED}✗ Not reachable${NC}"
    echo "  Make sure Victim VM is running"
fi

# Test Attacker VM
echo -n "  Attacker VM (192.168.128.101): "
if ping -c 1 -W 2 $ATTACKER_IP > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Reachable${NC}"
else
    echo -e "${RED}✗ Not reachable${NC}"
    echo "  Make sure Attacker VM is running"
fi

echo ""

# =============================================================================
# PHASE 2: Project Deployment
# =============================================================================
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}PHASE 2: Project Deployment${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo ""

echo "Deploying SecureNet project to VMs..."
echo ""

# Deploy to each VM
deploy_vm() {
    local vm_name=$1
    local vm_ip=$2
    local vm_user=$3
    
    echo -n "  Deploying to $vm_name ($vm_ip): "
    
    # Check if sshpass is available for password auth
    if ! command -v sshpass &> /dev/null; then
        # Install sshpass if not available
        brew install sshpass 2>/dev/null || true
    fi
    
    # Try SSH with password
    if ! sshpass -p "$VM_PASSWORD" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 -o UserKnownHostsFile=/dev/null $vm_user@$vm_ip "exit" > /dev/null 2>&1; then
        echo -e "${RED}✗ Cannot connect${NC}"
        return 1
    fi
    
    # Deploy via tar over SSH
    cd "$PROJECT_DIR"
    tar czf - \
        --exclude='.venv' \
        --exclude='__pycache__' \
        --exclude='.git' \
        --exclude='*.pyc' \
        --exclude='logs/*' \
        --exclude='*.log' \
        . 2>/dev/null | sshpass -p "$VM_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $vm_user@$vm_ip "
            mkdir -p ~/securenet
            cd ~/securenet
            tar xzf - 2>/dev/null
            chmod +x scripts/*.sh *.sh 2>/dev/null
        " 2>/dev/null
    
    echo -e "${GREEN}✓ Deployed${NC}"
    return 0
}

DEPLOY_SUCCESS=0

if deploy_vm "Monitor VM" "$MONITOR_IP" "$MONITOR_USER"; then
    DEPLOY_SUCCESS=$((DEPLOY_SUCCESS + 1))
fi

if deploy_vm "Victim VM" "$VICTIM_IP" "$VICTIM_USER"; then
    DEPLOY_SUCCESS=$((DEPLOY_SUCCESS + 1))
fi

if deploy_vm "Attacker VM" "$ATTACKER_IP" "$ATTACKER_USER"; then
    DEPLOY_SUCCESS=$((DEPLOY_SUCCESS + 1))
fi

echo ""
echo -e "${YELLOW}Deployed to $DEPLOY_SUCCESS/3 VMs${NC}"
echo ""

# =============================================================================
# PHASE 3: VM Setup Scripts
# =============================================================================
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}PHASE 3: Running VM Setup Scripts${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo ""

echo "This phase takes ~5-10 minutes per VM. Running in sequence..."
echo ""

run_setup() {
    local vm_name=$1
    local vm_ip=$2
    local vm_user=$3
    local script_name=$4
    
    echo -e "${YELLOW}Setting up $vm_name ($vm_ip)...${NC}"
    
    if ! sshpass -p "$VM_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 $vm_user@$vm_ip "exit" > /dev/null 2>&1; then
        echo -e "${RED}✗ Cannot connect to $vm_name${NC}"
        return 1
    fi
    
    sshpass -p "$VM_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $vm_user@$vm_ip "
        cd ~/securenet
        bash scripts/$script_name
    " 2>/dev/null
    
    echo -e "${GREEN}✓ $vm_name setup complete${NC}"
    echo ""
    return 0
}

run_setup "Monitor VM" "$MONITOR_IP" "$MONITOR_USER" "setup_monitor_vm.sh"
run_setup "Victim VM" "$VICTIM_IP" "$VICTIM_USER" "setup_victim_vm.sh"
run_setup "Attacker VM" "$ATTACKER_IP" "$ATTACKER_USER" "setup_attacker_vm.sh"

# =============================================================================
# PHASE 4: Installation of Project Requirements
# =============================================================================
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}PHASE 4: Installing Project Requirements${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo ""

install_project() {
    local vm_name=$1
    local vm_ip=$2
    local vm_user=$3
    
    echo -n "  Installing on $vm_name: "
    
    sshpass -p "$VM_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $vm_user@$vm_ip "
        cd ~/securenet
        pip3 install -q -r requirements.txt
        pip3 install -q -e .
    " 2>/dev/null && echo -e "${GREEN}✓ Done${NC}" || echo -e "${RED}✗ Failed${NC}"
}

install_project "Monitor VM" "$MONITOR_IP" "$MONITOR_USER"
install_project "Victim VM" "$VICTIM_IP" "$VICTIM_USER"
install_project "Attacker VM" "$ATTACKER_IP" "$ATTACKER_USER"

echo ""

# =============================================================================
# COMPLETION
# =============================================================================
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✅ QUICKSTART COMPLETE!${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo ""

echo "System Status:"
echo "  Monitor VM:  sshpass -p $VM_PASSWORD ssh $MONITOR_USER@$MONITOR_IP"
echo "  Victim VM:   sshpass -p $VM_PASSWORD ssh $VICTIM_USER@$VICTIM_IP"
echo "  Attacker VM: sshpass -p $VM_PASSWORD ssh $ATTACKER_USER@$ATTACKER_IP"
echo ""

echo "Next Steps:"
echo ""
echo "1️⃣  Create baseline on Monitor VM:"
echo "   ssh monitor@$MONITOR_IP"
echo "   cd ~/securenet"
echo "   python3 -m lan_security_system.baseline create --interface enp0s1"
echo ""
echo "2️⃣  Start the detection system:"
echo "   python3 production_main.py --interface enp0s1"
echo ""
echo "3️⃣  On Attacker VM, run an attack:"
echo "   ssh attacker@$ATTACKER_IP"
echo "   cd ~/securenet"
echo "   sudo python3 attack_scripts/arp_spoof.py"
echo ""
echo "4️⃣  Watch detection and mitigation on Monitor VM"
echo ""

echo "Documentation:"
echo "  - Architecture: SETUP_HOME_LAB.md"
echo "  - Deployment: PRODUCTION_DEPLOYMENT_SUMMARY.md"
echo "  - Enhancements: ENHANCEMENT_SUMMARY.md"
echo ""
