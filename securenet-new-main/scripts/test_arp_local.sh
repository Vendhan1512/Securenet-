#!/bin/bash
# Simple ARP Attack Simulation
# Runs on Monitor VM to test detection

sshpass -p "achu2006" ssh monitor@192.168.128.8 "
  cd ~/securenet
  
  echo '🔍 ARP Detection System Active'
  echo '========================================'
  echo ''
  
  # Create a Python script to simulate ARP packets
  python3 << 'PYTHON'
import subprocess
import time
from datetime import datetime

print('Simulating ARP spoofing packets...')
print(f'Time: {datetime.now().strftime(\"%Y-%m-%d %H:%M:%S\")}')
print('')

# Generate ARP request packets (normal traffic first)
print('📨 Normal ARP traffic (3 packets)...')
for i in range(3):
    # Using arping to send normal ARP requests
    try:
        subprocess.run(
            ['sudo', 'arping', '-c', '1', '192.168.128.1'],
            capture_output=True,
            timeout=2
        )
        print(f'  [{i+1}] ARP request sent')
        time.sleep(0.5)
    except Exception as e:
        print(f'  Error: {e}')

print('')
print('🚨 Simulating ARP spoofing (high rate)...')

# Simulate ARP flood
try:
    proc = subprocess.Popen(
        ['sudo', 'arpspoof', '-i', 'enp0s1', '-t', '192.168.128.1', '192.168.128.6'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    print('  Starting ARP spoof (5 seconds)...')
    time.sleep(5)
    proc.terminate()
    proc.wait(timeout=2)
    print('  ARP spoof stopped')
    
except Exception as e:
    print(f'  Spoof attempt: {e}')

print('')
print('✓ Simulation complete')
PYTHON

  echo ''
  echo '========================================'
  echo 'Checking detection logs...'
  echo ''
  tail -20 lan_security.log | grep -E 'ARP|Spoof|anomaly' || echo 'No ARP attacks detected in logs'
" 2>/dev/null