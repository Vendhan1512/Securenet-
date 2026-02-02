#!/bin/bash
# Monitor VM Setup Script
# Usage: ssh monitor@192.168.100.8 'bash -s' < setup_monitor_vm.sh

set -e

echo "╔════════════════════════════════════════════════╗"
echo "║   SecureNet Monitor VM Setup Script            ║"
echo "║   Setting up security monitoring system        ║"
echo "╚════════════════════════════════════════════════╝"
echo ""

# =============================================================================
# STEP 1: System Update
# =============================================================================
echo "📦 STEP 1: Updating system packages..."
sudo apt-get update -qq
sudo apt-get upgrade -y -qq
echo "✅ System updated"
echo ""

# =============================================================================
# STEP 2: Hostname Configuration
# =============================================================================
echo "🏷️  STEP 2: Configuring hostname..."
sudo hostnamectl set-hostname monitor-security
echo "127.0.0.1 monitor-security" | sudo tee -a /etc/hosts > /dev/null
echo "✅ Hostname set to: monitor-security"
echo ""

# =============================================================================
# STEP 3: Network Configuration (Static IP)
# =============================================================================
echo "🌐 STEP 3: Configuring static IP (192.168.100.8/24)..."

# Detect interface
INTERFACE=$(ip link show | grep "enp0s1\|eth0\|ens3" | head -1 | awk '{print $2}' | sed 's/:$//')

if [ -z "$INTERFACE" ]; then
    echo "❌ Could not detect network interface"
    echo "Available interfaces:"
    ip link show
    exit 1
fi

echo "   Using interface: $INTERFACE"

# Create netplan config
sudo tee /etc/netplan/00-installer-config.yaml > /dev/null << 'EOF'
network:
  version: 2
  ethernets:
    enp0s1:
      dhcp4: no
      addresses:
        - 192.168.128.8/24
      routes:
        - to: 0.0.0.0/0
          via: 192.168.128.1
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]
EOF

sudo netplan apply
echo "✅ Static IP configured"
echo ""

# =============================================================================
# STEP 4: Install Dependencies
# =============================================================================
echo "🔧 STEP 4: Installing dependencies..."
sudo apt-get install -y -qq \
    python3-pip \
    python3-dev \
    python3-venv \
    libpcap-dev \
    gcc \
    git \
    curl \
    vim \
    net-tools \
    tcpdump \
    wireshark-common \
    hping3 \
    jq

echo "✅ Dependencies installed"
echo ""

# =============================================================================
# STEP 5: Python Package Installation
# =============================================================================
echo "🐍 STEP 5: Installing Python packages..."
pip3 install --upgrade -q pip setuptools wheel
pip3 install -q \
    scapy \
    pydantic \
    pyyaml \
    fastapi \
    uvicorn \
    psutil \
    netaddr

echo "✅ Python packages installed"
echo ""

# =============================================================================
# STEP 6: Create Directory Structure
# =============================================================================
echo "📁 STEP 6: Creating directory structure..."
mkdir -p ~/securenet
mkdir -p ~/securenet/logs
mkdir -p ~/securenet/config
mkdir -p ~/securenet/baselines
sudo mkdir -p /opt/securenet/logs
sudo mkdir -p /opt/securenet/baselines
sudo chown -R $(whoami):$(whoami) /opt/securenet

echo "✅ Directories created"
echo ""

# =============================================================================
# STEP 7: Verify tcpdump permissions
# =============================================================================
echo "🔐 STEP 7: Setting up packet capture permissions..."
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
sudo usermod -a -G wireshark $(whoami)

echo "✅ Packet capture permissions configured"
echo ""

# =============================================================================
# STEP 8: Configuration Files
# =============================================================================
echo "⚙️  STEP 8: Creating configuration files..."

cat > ~/securenet/production_config.yaml << 'EOF'
network:
  default_interface: enp0s1
  lab_subnet: 192.168.100.0/24
  capture_buffer_size: 131072

detection:
  arp_rate_threshold: 10
  mac_learning_threshold: 50
  dns_safe_mode: false
  detection_window_size: 30
  detection_latency_target: 50
  false_positive_threshold: 0.02

mitigation:
  enabled: true
  auto_recover: true
  recovery_timeout: 30

alerting:
  console_alerts: true
  log_file: /opt/securenet/logs/production_security.log
  event_log: /opt/securenet/logs/security_events.jsonl
  syslog_enabled: true

api:
  enabled: true
  bind_host: 0.0.0.0
  bind_port: 8000
EOF

echo "✅ Configuration files created"
echo ""

# =============================================================================
# STEP 9: Test Packet Capture
# =============================================================================
echo "🧪 STEP 9: Testing packet capture capability..."
if sudo timeout 3 tcpdump -i $INTERFACE -c 1 2>/dev/null; then
    echo "✅ Packet capture working"
else
    echo "⚠️  Packet capture test timed out (expected if no network traffic)"
fi
echo ""

# =============================================================================
# STEP 10: Final Verification
# =============================================================================
echo "✔️  STEP 10: Running verification checks..."

echo "  Checking hostname..."
hostname | grep -q "monitor-security" && echo "    ✓ Hostname: monitor-security" || echo "    ✗ Hostname issue"

echo "  Checking IP address..."
ip addr show $INTERFACE | grep -q "192.168.100.8" && echo "    ✓ IP: 192.168.100.8" || echo "    ✗ IP not configured"

echo "  Checking Python..."
python3 --version | grep -q "3\." && echo "    ✓ Python 3 installed" || echo "    ✗ Python 3 issue"

echo "  Checking Scapy..."
python3 -c "from scapy.all import *; print('    ✓ Scapy available')" || echo "    ✗ Scapy issue"

echo "  Checking tcpdump..."
which tcpdump > /dev/null && echo "    ✓ tcpdump available" || echo "    ✗ tcpdump issue"

echo ""
echo "╔════════════════════════════════════════════════╗"
echo "║      Monitor VM Setup Complete! ✅            ║"
echo "╚════════════════════════════════════════════════╝"
echo ""
echo "Next steps:"
echo "  1. Copy project files to ~/securenet:"
echo "     scp -r /path/to/securenet-new monitor@192.168.100.8:~/securenet"
echo ""
echo "  2. Install the project:"
echo "     cd ~/securenet"
echo "     pip3 install -e ."
echo ""
echo "  3. Create network baseline:"
echo "     sudo python3 -m lan_security_system.baseline create --interface enp0s1"
echo ""
echo "  4. Start the system:"
echo "     sudo python3 production_main.py --interactive --interface enp0s1 --config production_config.yaml --log-level INFO"
echo ""
echo "  5. View logs:"
echo "     tail -f /opt/securenet/logs/production_security.log"
echo ""
