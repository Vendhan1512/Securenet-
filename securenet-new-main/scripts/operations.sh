#!/bin/bash
# SecureNet Operations Helper
# Common commands for running detection, mitigation, and attacks
# Usage: bash operations.sh [command] [args]

set -e

# Configuration
MONITOR_IP="192.168.128.8"
VICTIM_IP="192.168.128.6"
ATTACKER_IP="192.168.128.101"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# =============================================================================
# Helper Functions
# =============================================================================

show_menu() {
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║        SecureNet Operations Menu                       ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Detection & Baseline:"
    echo "  1. Create baseline on Monitor VM"
    echo "  2. Check baseline status"
    echo "  3. Start detection (production_main.py)"
    echo ""
    echo "Attacks (Run on Attacker VM):"
    echo "  4. Run ARP spoofing attack"
    echo "  5. Run MAC flooding attack"
    echo "  6. Run DNS spoofing attack"
    echo ""
    echo "System Info:"
    echo "  7. Check Monitor VM status"
    echo "  8. View Monitor VM logs"
    echo "  9. Check all VM connectivity"
    echo ""
    echo "Advanced:"
    echo "  10. SSH to Monitor VM"
    echo "  11. SSH to Victim VM"
    echo "  12. SSH to Attacker VM"
    echo "  13. Deploy code changes"
    echo ""
    echo "  0. Exit"
    echo ""
}

# =============================================================================
# Detection & Baseline Commands
# =============================================================================

create_baseline() {
    echo -e "${YELLOW}Creating baseline on Monitor VM...${NC}"
    echo ""
    
    ssh monitor@$MONITOR_IP "
        cd ~/securenet
        echo 'Creating baseline snapshot...'
        python3 -m lan_security_system.baseline create --interface enp0s1
        echo ''
        echo 'Baseline created. Next step: run detection'
    "
}

check_baseline() {
    echo -e "${YELLOW}Checking baseline status...${NC}"
    echo ""
    
    ssh monitor@$MONITOR_IP "
        if [ -d ~/securenet/baselines ]; then
            echo 'Baseline directory exists'
            ls -lah ~/securenet/baselines/
        else
            echo 'No baseline created yet. Run: create_baseline'
        fi
    "
}

start_detection() {
    echo -e "${YELLOW}Starting detection system...${NC}"
    echo ""
    echo "This will run in the foreground. Press Ctrl+C to stop."
    echo ""
    
    ssh -t monitor@$MONITOR_IP "
        cd ~/securenet
        echo 'Starting detection system (production_main.py)...'
        echo 'Press Ctrl+C to stop'
        echo ''
        python3 production_main.py --interface enp0s1
    "
}

# =============================================================================
# Attack Commands
# =============================================================================

arp_spoof_attack() {
    echo -e "${YELLOW}Running ARP spoofing attack from Attacker VM...${NC}"
    echo ""
    
    ssh attacker@$ATTACKER_IP "
        cd ~/securenet
        echo 'ARP Spoofing Attack'
        echo 'Target: 192.168.100.6 (Victim)'
        echo 'Gateway: 192.168.100.1'
        echo ''
        sudo python3 scripts/attack_scripts/arp_spoof.py \
            --victim 192.168.100.6 \
            --gateway 192.168.100.1 \
            --interface eth0 \
            --count 500
    "
}

mac_flood_attack() {
    echo -e "${YELLOW}Running MAC flooding attack from Attacker VM...${NC}"
    echo ""
    
    ssh attacker@$ATTACKER_IP "
        cd ~/securenet
        echo 'MAC Flooding Attack'
        echo 'Target: 192.168.100.6 (Victim)'
        echo ''
        sudo python3 scripts/attack_scripts/mac_flood.py \
            --target 192.168.100.6 \
            --attacker 192.168.100.101 \
            --interface eth0 \
            --count 1000
    "
}

dns_spoof_attack() {
    echo -e "${YELLOW}Running DNS spoofing attack from Attacker VM...${NC}"
    echo ""
    
    ssh attacker@$ATTACKER_IP "
        cd ~/securenet
        echo 'DNS Spoofing Attack'
        echo 'Target: 192.168.100.6 (Victim)'
        echo 'Domain: google.com'
        echo ''
        sudo python3 scripts/attack_scripts/dns_spoof.py \
            --victim 192.168.100.6 \
            --attacker 192.168.100.101 \
            --interface eth0 \
            --domain google.com \
            --count 50
    "
}

# =============================================================================
# System Info Commands
# =============================================================================

monitor_status() {
    echo -e "${YELLOW}Checking Monitor VM status...${NC}"
    echo ""
    
    ssh monitor@$MONITOR_IP "
        echo 'System Information:'
        echo '─────────────────'
        hostname
        echo ''
        echo 'Network Interface (enp0s1):'
        ip addr show enp0s1
        echo ''
        echo 'Detection System:'
        if [ -d ~/securenet ]; then
            echo '✓ Project installed'
            if [ -d ~/securenet/baselines ]; then
                echo '✓ Baseline exists'
            else
                echo '✗ No baseline (run: create_baseline)'
            fi
        else
            echo '✗ Project not installed'
        fi
    "
}

view_logs() {
    echo -e "${YELLOW}Monitor VM Security Logs (last 20 events)...${NC}"
    echo ""
    
    ssh monitor@$MONITOR_IP "
        if [ -f ~/securenet/logs/security_events.jsonl ]; then
            echo 'Recent security events:'
            tail -20 ~/securenet/logs/security_events.jsonl | jq -r '.timestamp + \" \" + .event_type + \": \" + .description' 2>/dev/null || tail -20 ~/securenet/logs/security_events.jsonl
        else
            echo 'No security logs found yet'
        fi
    "
}

check_connectivity() {
    echo -e "${YELLOW}Checking VM Connectivity...${NC}"
    echo ""
    
    echo -n "Monitor VM (192.168.100.8):  "
    timeout 2 ping -c 1 $MONITOR_IP > /dev/null 2>&1 && echo -e "${GREEN}✓${NC}" || echo -e "${RED}✗${NC}"
    
    echo -n "Victim VM (192.168.100.6):   "
    timeout 2 ping -c 1 $VICTIM_IP > /dev/null 2>&1 && echo -e "${GREEN}✓${NC}" || echo -e "${RED}✗${NC}"
    
    echo -n "Attacker VM (192.168.100.101): "
    timeout 2 ping -c 1 $ATTACKER_IP > /dev/null 2>&1 && echo -e "${GREEN}✓${NC}" || echo -e "${RED}✗${NC}"
    
    echo ""
}

# =============================================================================
# SSH Access Commands
# =============================================================================

ssh_monitor() {
    echo -e "${YELLOW}Connecting to Monitor VM...${NC}"
    ssh monitor@$MONITOR_IP
}

ssh_victim() {
    echo -e "${YELLOW}Connecting to Victim VM...${NC}"
    ssh victim@$VICTIM_IP
}

ssh_attacker() {
    echo -e "${YELLOW}Connecting to Attacker VM...${NC}"
    ssh attacker@$ATTACKER_IP
}

deploy_changes() {
    echo -e "${YELLOW}Deploying code changes to all VMs...${NC}"
    echo ""
    bash scripts/deploy_to_vms.sh
    echo ""
    echo "Re-installing packages..."
    ssh monitor@$MONITOR_IP "cd ~/securenet && pip3 install -q -e ."
    ssh victim@$VICTIM_IP "cd ~/securenet && pip3 install -q -e ."
    ssh attacker@$ATTACKER_IP "cd ~/securenet && pip3 install -q -e ."
    echo -e "${GREEN}✓ Deployment complete${NC}"
}

# =============================================================================
# Main Menu
# =============================================================================

if [ $# -eq 0 ]; then
    # Interactive mode
    while true; do
        show_menu
        read -p "Select option (0-13): " choice
        
        case $choice in
            1) create_baseline ;;
            2) check_baseline ;;
            3) start_detection ;;
            4) arp_spoof_attack ;;
            5) mac_flood_attack ;;
            6) dns_spoof_attack ;;
            7) monitor_status ;;
            8) view_logs ;;
            9) check_connectivity ;;
            10) ssh_monitor ;;
            11) ssh_victim ;;
            12) ssh_attacker ;;
            13) deploy_changes ;;
            0) echo "Exiting..."; exit 0 ;;
            *) echo -e "${RED}Invalid option${NC}" ;;
        esac
        
        read -p "Press Enter to continue..."
    done
else
    # Command line mode
    case "$1" in
        baseline-create) create_baseline ;;
        baseline-check) check_baseline ;;
        detection-start) start_detection ;;
        attack-arp) arp_spoof_attack ;;
        attack-mac) mac_flood_attack ;;
        attack-dns) dns_spoof_attack ;;
        status) monitor_status ;;
        logs) view_logs ;;
        connectivity) check_connectivity ;;
        ssh-monitor) ssh_monitor ;;
        ssh-victim) ssh_victim ;;
        ssh-attacker) ssh_attacker ;;
        deploy) deploy_changes ;;
        *)
            echo "Usage: bash operations.sh [command]"
            echo ""
            echo "Commands:"
            echo "  baseline-create     - Create baseline on Monitor VM"
            echo "  baseline-check      - Check baseline status"
            echo "  detection-start     - Start detection (production_main.py)"
            echo "  attack-arp          - Run ARP spoofing attack"
            echo "  attack-mac          - Run MAC flooding attack"
            echo "  attack-dns          - Run DNS spoofing attack"
            echo "  status              - Check Monitor VM status"
            echo "  logs                - View security logs"
            echo "  connectivity        - Check VM connectivity"
            echo "  ssh-monitor         - SSH to Monitor VM"
            echo "  ssh-victim          - SSH to Victim VM"
            echo "  ssh-attacker        - SSH to Attacker VM"
            echo "  deploy              - Deploy code changes"
            echo ""
            echo "Or run without arguments for interactive menu:"
            echo "  bash operations.sh"
            ;;
    esac
fi
