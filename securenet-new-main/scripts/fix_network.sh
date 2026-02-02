#!/bin/bash
# macOS Network Configuration Helper
# Fixes Hypervisor Host-Only Network to allow VM connectivity
# Usage: bash fix_network.sh

echo "╔════════════════════════════════════════════════════════╗"
echo "║   SecureNet Network Configuration Helper               ║"
echo "║   Fixes Host-Only Bridge Network Subnet Mismatch       ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# =============================================================================
# Step 1: Detect Current Network Configuration
# =============================================================================
echo -e "${BLUE}Step 1: Detecting current network configuration...${NC}"
echo ""

echo "macOS network interfaces:"
ifconfig | grep -E "^[a-z]|inet " | head -20
echo ""

# Check bridge networks
echo "Host-Only Bridge Networks:"
ifconfig | grep -B1 "inet 192.168"
echo ""

# =============================================================================
# Step 2: Detect Hypervisor Type
# =============================================================================
echo -e "${BLUE}Step 2: Detecting hypervisor type...${NC}"
echo ""

HYPERVISOR=""

if pgrep -q "Parallels"; then
    HYPERVISOR="Parallels"
    echo -e "${GREEN}✓ Parallels Desktop detected${NC}"
elif pgrep -q "VirtualBox"; then
    HYPERVISOR="VirtualBox"
    echo -e "${GREEN}✓ VirtualBox detected${NC}"
elif pgrep -q "vmware-vmx"; then
    HYPERVISOR="VMware"
    echo -e "${GREEN}✓ VMware Fusion detected${NC}"
elif pgrep -q "qemu"; then
    HYPERVISOR="UTM"
    echo -e "${GREEN}✓ UTM detected${NC}"
else
    echo -e "${YELLOW}⚠ Could not auto-detect hypervisor${NC}"
    echo ""
    echo "Available hypervisors:"
    echo "  1. Parallels Desktop"
    echo "  2. VMware Fusion"
    echo "  3. VirtualBox"
    echo "  4. UTM"
    echo ""
    read -p "Select hypervisor (1-4): " choice
    case $choice in
        1) HYPERVISOR="Parallels" ;;
        2) HYPERVISOR="VMware" ;;
        3) HYPERVISOR="VirtualBox" ;;
        4) HYPERVISOR="UTM" ;;
        *) echo "Invalid choice"; exit 1 ;;
    esac
fi

echo ""

# =============================================================================
# Step 3: Current Network Diagnosis
# =============================================================================
echo -e "${BLUE}Step 3: Current network diagnosis...${NC}"
echo ""

echo "Testing connectivity to Monitor VM (192.168.100.8):"
if ping -c 1 -W 2 192.168.100.8 > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Monitor VM is reachable${NC}"
else
    echo -e "${RED}✗ Monitor VM is NOT reachable (expected - will fix)${NC}"
fi

echo ""
echo "Current bridge IP: $(ifconfig | grep -A1 'bridge100' | grep inet | awk '{print $2}')"
echo "Expected bridge IP: 192.168.100.1 (or similar in 192.168.100.0/24)"
echo "Target VM IPs: 192.168.100.6 (Victim), 192.168.100.8 (Monitor), 192.168.100.101 (Attacker)"
echo ""

# =============================================================================
# Step 4: Hypervisor-Specific Instructions
# =============================================================================
echo -e "${BLUE}Step 4: Hypervisor-Specific Configuration${NC}"
echo ""

if [ "$HYPERVISOR" = "Parallels" ]; then
    echo -e "${YELLOW}Parallels Desktop Instructions:${NC}"
    echo ""
    echo "1. Open Parallels Control Center (or Parallels Desktop menu)"
    echo "2. Go to: Parallels Desktop → Settings"
    echo "3. Navigate to: Network → Host-Only Networks"
    echo "4. Look for 'vnic0' or similar"
    echo "5. Edit the network and change:"
    echo "   - Network: 192.168.100.0/24"
    echo "   - Gateway: 192.168.100.1"
    echo "6. Apply changes"
    echo "7. Run the connectivity test below"
    echo ""
    echo "Command line alternative (if available):"
    echo "   defaults read com.parallels.Parallels | grep -i network"
    
elif [ "$HYPERVISOR" = "VMware" ]; then
    echo -e "${YELLOW}VMware Fusion Instructions:${NC}"
    echo ""
    echo "1. Open VMware Fusion"
    echo "2. Go to: VMware Fusion → Preferences"
    echo "3. Select: Network"
    echo "4. Find the Host-Only adapter (likely vmnet1 or similar)"
    echo "5. Click the 'Edit' button for that adapter"
    echo "6. Change settings to:"
    echo "   - Configure: Manually"
    echo "   - Subnet IP: 192.168.100.0"
    echo "   - Subnet Mask: 255.255.255.0"
    echo "   - Gateway: 192.168.100.1"
    echo "7. Apply and restart VMware"
    echo "8. Restart the VMs"
    echo ""
    
elif [ "$HYPERVISOR" = "VirtualBox" ]; then
    echo -e "${YELLOW}VirtualBox Instructions:${NC}"
    echo ""
    echo "1. Open VirtualBox Manager"
    echo "2. Go to: VirtualBox → Preferences (or Settings)"
    echo "3. Select: Network"
    echo "4. Click 'Host-only Networks' tab"
    echo "5. Look for 'vboxnet0' - click to select"
    echo "6. Click the screwdriver icon to edit"
    echo "7. In 'Adapter' tab, set:"
    echo "   - IPv4 Address: 192.168.100.1"
    echo "   - IPv4 Network Mask: 255.255.255.0"
    echo "8. In 'DHCP Server' tab (if using DHCP):"
    echo "   - Server Address: 192.168.100.1"
    echo "   - Server Mask: 255.255.255.0"
    echo "   - Lower Address Bound: 192.168.100.100"
    echo "   - Upper Address Bound: 192.168.100.254"
    echo "9. Click OK and OK again to apply"
    echo "10. Restart the VMs"
    echo ""
    
elif [ "$HYPERVISOR" = "UTM" ]; then
    echo -e "${YELLOW}UTM Instructions:${NC}"
    echo ""
    echo "1. Open UTM"
    echo "2. For each VM:"
    echo "   - Select the VM"
    echo "   - Edit → Network"
    echo "   - Ensure it's set to 'Host Only'"
    echo "3. On macOS host, check network:"
    echo "   - System Settings → Network"
    echo "   - Look for the UTM bridge (often tap or utun interface)"
    echo "4. If needed, create/configure bridge:"
    echo "   - System Settings → Network → Add Interface"
    echo "   - Create new interface for host-only bridging"
    echo ""
fi

# =============================================================================
# Step 5: Post-Configuration Testing
# =============================================================================
echo ""
echo -e "${BLUE}Step 5: Testing connectivity after configuration${NC}"
echo ""

read -p "Have you applied the hypervisor configuration? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "Testing connectivity to VMs..."
    echo ""
    
    echo -n "Monitor VM (192.168.100.8): "
    if ping -c 1 -W 2 192.168.100.8 > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Reachable${NC}"
    else
        echo -e "${RED}✗ Not reachable${NC}"
    fi
    
    echo -n "Victim VM (192.168.100.6):  "
    if ping -c 1 -W 2 192.168.100.6 > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Reachable${NC}"
    else
        echo -e "${RED}✗ Not reachable${NC}"
    fi
    
    echo -n "Attacker VM (192.168.100.101): "
    if ping -c 1 -W 2 192.168.100.101 > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Reachable${NC}"
    else
        echo -e "${RED}✗ Not reachable${NC}"
    fi
    
    echo ""
    
    # If all VMs are reachable
    if ping -c 1 -W 2 192.168.100.8 > /dev/null 2>&1 && \
       ping -c 1 -W 2 192.168.100.6 > /dev/null 2>&1; then
        echo -e "${GREEN}✅ All VMs are reachable!${NC}"
        echo ""
        echo "Next steps:"
        echo "  1. Deploy project to VMs:"
        echo "     bash scripts/deploy_to_vms.sh"
        echo ""
        echo "  2. Run setup scripts on each VM:"
        echo "     ssh monitor@192.168.100.8 'cd ~/securenet && bash scripts/setup_monitor_vm.sh'"
        echo "     ssh victim@192.168.100.6 'cd ~/securenet && bash scripts/setup_victim_vm.sh'"
        echo "     ssh attacker@192.168.100.101 'cd ~/securenet && bash scripts/setup_attacker_vm.sh'"
    else
        echo -e "${RED}⚠ Some VMs are still not reachable${NC}"
        echo ""
        echo "Troubleshooting:"
        echo "  1. Verify VMs are powered on"
        echo "  2. Check VM network adapter is set to Host-Only"
        echo "  3. Verify VM has correct static IP (192.168.100.x)"
        echo "  4. On Monitor VM, test: ping 192.168.100.1"
        echo "  5. Check hypervisor bridge: ifconfig | grep 192.168.100"
    fi
else
    echo ""
    echo "Please apply the configuration above, then run this script again."
fi

echo ""
