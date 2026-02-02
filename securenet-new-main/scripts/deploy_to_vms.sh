#!/bin/bash
# Deploy SecureNet Project to VMs
# Usage: ./deploy_to_vms.sh [monitor-ip] [victim-ip] [attacker-ip]

set -e

MONITOR_IP="${1:-192.168.128.8}"
VICTIM_IP="${2:-192.168.128.6}"
ATTACKER_IP="${3:-192.168.128.101}"
PROJECT_DIR="/Users/aswanthb/Desktop/securenet-new"

echo "╔════════════════════════════════════════════════╗"
echo "║         SecureNet Deployment Script            ║"
echo "║   Deploying to Monitor, Victim, and Attacker   ║"
echo "╚════════════════════════════════════════════════╝"
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# =============================================================================
# Function to deploy to a VM
# =============================================================================
deploy_to_vm() {
    local vm_type=$1
    local vm_ip=$2
    local vm_user=$3
    
    echo -e "${YELLOW}Deploying to $vm_type ($vm_ip)...${NC}"
    
    # Check SSH connectivity
    if ! ssh -o ConnectTimeout=5 $vm_user@$vm_ip "exit" > /dev/null 2>&1; then
        echo -e "${RED}✗ Cannot connect to $vm_type at $vm_ip${NC}"
        echo "  Make sure the VM is running and SSH is accessible"
        return 1
    fi
    
    echo "  Compressing project..."
    cd "$PROJECT_DIR"
    tar czf - \
        --exclude='.venv' \
        --exclude='__pycache__' \
        --exclude='.git' \
        --exclude='*.pyc' \
        --exclude='logs/*' \
        --exclude='*.log' \
        . | ssh $vm_user@$vm_ip "
            echo '  Extracting project...'
            mkdir -p ~/securenet
            cd ~/securenet
            tar xzf -
            echo '  Setting permissions...'
            chmod +x *.sh
            chmod +x scripts/*.sh
            echo -e '${GREEN}✓ Deployment complete${NC}'
        "
    
    echo -e "${GREEN}✓ $vm_type deployed${NC}"
    echo ""
    return 0
}

# =============================================================================
# Deployment Steps
# =============================================================================

echo "🔍 Checking connectivity..."
echo ""

# Deploy to Monitor
if deploy_to_vm "Monitor VM" "$MONITOR_IP" "monitor"; then
    echo "📋 Next steps for Monitor VM:"
    echo "   ssh monitor@$MONITOR_IP"
    echo "   cd ~/securenet && bash scripts/setup_monitor_vm.sh"
    echo ""
fi

# Deploy to Victim
if deploy_to_vm "Victim VM" "$VICTIM_IP" "victim"; then
    echo "📋 Next steps for Victim VM:"
    echo "   ssh victim@$VICTIM_IP"
    echo "   cd ~/securenet && bash scripts/setup_victim_vm.sh"
    echo ""
fi

# Deploy to Attacker
if deploy_to_vm "Attacker VM" "$ATTACKER_IP" "attacker"; then
    echo "📋 Next steps for Attacker VM:"
    echo "   ssh attacker@$ATTACKER_IP"
    echo "   cd ~/securenet && bash scripts/setup_attacker_vm.sh"
    echo ""
fi

echo "╔════════════════════════════════════════════════╗"
echo "║   Deployment Complete! Run setup scripts        ║"
echo "╚════════════════════════════════════════════════╝"
echo ""
