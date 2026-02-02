#!/bin/bash
# Fast deployment using scp instead of tar+ssh
# Much faster and more reliable

set -e

PROJECT_DIR="/Users/aswanthb/Desktop/securenet-new"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# VM Credentials
MONITOR_IP="192.168.128.8"
VICTIM_IP="192.168.128.6"
ATTACKER_IP="192.168.128.101"

MONITOR_USER="monitor"
VICTIM_USER="achu2"
ATTACKER_USER="achu"
VM_PASSWORD="achu2006"

echo -e "${BLUE}════════════════════════════════════════${NC}"
echo -e "${BLUE}SecureNet Fast Deployment${NC}"
echo -e "${BLUE}════════════════════════════════════════${NC}"
echo ""

# Deploy to a VM
deploy_to_vm() {
    local vm_name=$1
    local vm_ip=$2
    local vm_user=$3
    
    echo -e "${YELLOW}Deploying to $vm_name ($vm_ip)...${NC}"
    
    # Create remote directory
    sshpass -p "$VM_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $vm_user@$vm_ip "
        rm -rf ~/securenet
        mkdir -p ~/securenet
    " 2>/dev/null
    
    # Copy main files
    echo "  Copying Python files..."
    sshpass -p "$VM_PASSWORD" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        $PROJECT_DIR/*.py \
        $PROJECT_DIR/*.yaml \
        $PROJECT_DIR/*.sh \
        $PROJECT_DIR/requirements.txt \
        $vm_user@$vm_ip:~/securenet/ 2>/dev/null || true
    
    # Copy lan_security_system directory
    echo "  Copying lan_security_system package..."
    sshpass -p "$VM_PASSWORD" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -r \
        $PROJECT_DIR/lan_security_system \
        $vm_user@$vm_ip:~/securenet/ 2>/dev/null || true
    
    # Copy scripts directory
    echo "  Copying scripts..."
    sshpass -p "$VM_PASSWORD" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -r \
        $PROJECT_DIR/scripts \
        $vm_user@$vm_ip:~/securenet/ 2>/dev/null || true
    
    # Make scripts executable
    sshpass -p "$VM_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $vm_user@$vm_ip "
        chmod +x ~/securenet/scripts/*.sh 2>/dev/null || true
        chmod +x ~/securenet/*.sh 2>/dev/null || true
    " 2>/dev/null
    
    echo -e "${GREEN}✓ $vm_name deployment complete${NC}"
    echo ""
}

# Deploy to all VMs
deploy_to_vm "Monitor VM" "$MONITOR_IP" "$MONITOR_USER"
deploy_to_vm "Victim VM" "$VICTIM_IP" "$VICTIM_USER"
deploy_to_vm "Attacker VM" "$ATTACKER_IP" "$ATTACKER_USER"

echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ All VMs deployed successfully!${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""

echo "Next steps:"
echo "1. Run setup scripts on each VM:"
echo "   sshpass -p achu2006 ssh monitor@192.168.128.8 'cd ~/securenet && bash scripts/setup_monitor_vm.sh'"
echo "   sshpass -p achu2006 ssh achu2@192.168.128.6 'cd ~/securenet && bash scripts/setup_victim_vm.sh'"
echo "   sshpass -p achu2006 ssh achu@192.168.128.101 'cd ~/securenet && bash scripts/setup_attacker_vm.sh'"
echo ""
echo "2. Or run the setup coordinator:"
echo "   bash scripts/setup_all_vms.sh"
