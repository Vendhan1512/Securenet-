#!/bin/bash
# Setup all VMs coordinator script

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
echo -e "${BLUE}SecureNet VM Setup Coordinator${NC}"
echo -e "${BLUE}This will configure all 3 VMs${NC}"
echo -e "${BLUE}(This takes 5-10 minutes per VM)${NC}"
echo -e "${BLUE}════════════════════════════════════════${NC}"
echo ""

# Function to setup a VM
setup_vm() {
    local vm_name=$1
    local vm_ip=$2
    local vm_user=$3
    local script=$4
    
    echo -e "${YELLOW}Setting up $vm_name ($vm_ip)...${NC}"
    
    sshpass -p "$VM_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $vm_user@$vm_ip "
        cd ~/securenet
        bash scripts/$script
    " 2>/dev/null
    
    echo -e "${GREEN}✓ $vm_name setup complete${NC}"
    echo ""
}

# Setup each VM
setup_vm "Monitor VM" "$MONITOR_IP" "$MONITOR_USER" "setup_monitor_vm.sh"
setup_vm "Victim VM" "$VICTIM_IP" "$VICTIM_USER" "setup_victim_vm.sh"
setup_vm "Attacker VM" "$ATTACKER_IP" "$ATTACKER_USER" "setup_attacker_vm.sh"

echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ All VMs configured successfully!${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""

echo "System is ready! You can now:"
echo ""
echo "1️⃣  SSH to any VM:"
echo "   sshpass -p achu2006 ssh monitor@192.168.128.8"
echo "   sshpass -p achu2006 ssh achu2@192.168.128.6"
echo "   sshpass -p achu2006 ssh achu@192.168.128.101"
echo ""
echo "2️⃣  Start the monitoring system:"
echo "   sshpass -p achu2006 ssh monitor@192.168.128.8 'cd ~/securenet && python3 main.py'"
echo ""
echo "3️⃣  Run tests from your Mac:"
echo "   bash scripts/operations.sh"
