#!/bin/bash
# Victim VM Setup Script
# Usage: ssh victim@192.168.100.6 'bash -s' < setup_victim_vm.sh

set -e

echo "╔════════════════════════════════════════════════╗"
echo "║    SecureNet Victim VM Setup Script            ║"
echo "║    Setting up protected network host           ║"
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
sudo hostnamectl set-hostname victim-host
echo "127.0.0.1 victim-host" | sudo tee -a /etc/hosts > /dev/null
echo "✅ Hostname set to: victim-host"
echo ""

# =============================================================================
# STEP 3: Network Configuration (Static IP)
# =============================================================================
echo "🌐 STEP 3: Configuring static IP (192.168.100.6/24)..."

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
        - 192.168.128.6/24
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
# STEP 4: Install Network Tools
# =============================================================================
echo "🔧 STEP 4: Installing network tools..."
sudo apt-get install -y -qq \
    net-tools \
    iputils-ping \
    curl \
    wget \
    dnsutils \
    netcat-openbsd \
    tcpdump

echo "✅ Network tools installed"
echo ""

# =============================================================================
# STEP 5: Enable IP Forwarding (for testing)
# =============================================================================
echo "🔀 STEP 5: Enabling IP forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "✅ IP forwarding enabled"
echo ""

# =============================================================================
# STEP 6: Start DNS Service
# =============================================================================
echo "🔍 STEP 6: Starting DNS resolver..."
sudo systemctl start systemd-resolved
sudo systemctl enable systemd-resolved
echo "✅ DNS resolver started"
echo ""

# =============================================================================
# STEP 7: Start HTTP Service (for traffic simulation)
# =============================================================================
echo "🌐 STEP 7: Installing HTTP server..."
sudo apt-get install -y -qq apache2
sudo systemctl start apache2
sudo systemctl enable apache2
echo "✅ HTTP server started"
echo ""

# =============================================================================
# STEP 8: Verify Connectivity
# =============================================================================
echo "✔️  STEP 8: Verifying connectivity..."

echo "  Testing ping to gateway..."
ping -c 1 192.168.100.1 > /dev/null && echo "    ✓ Gateway reachable" || echo "    ✗ Gateway not reachable"

echo "  Testing DNS..."
nslookup google.com > /dev/null 2>&1 && echo "    ✓ DNS working" || echo "    ✗ DNS issue"

echo "  Testing HTTP service..."
curl -s http://localhost > /dev/null && echo "    ✓ HTTP server working" || echo "    ✗ HTTP server issue"

echo ""
echo "╔════════════════════════════════════════════════╗"
echo "║      Victim VM Setup Complete! ✅             ║"
echo "╚════════════════════════════════════════════════╝"
echo ""
echo "Victim VM is now configured and ready to be attacked!"
echo ""
echo "Verify connectivity from other VMs:"
echo "  From Monitor: ping 192.168.100.6"
echo "  From Attacker: ping 192.168.100.6"
echo ""
