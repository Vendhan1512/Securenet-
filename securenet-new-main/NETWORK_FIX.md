# Network Configuration Issue - Solution

## Problem Detected

Your macOS host has a network mismatch:

**Current Configuration:**
- macOS WiFi (en0): 192.168.137.195
- macOS Host-Only Bridge: 192.168.128.1 ❌ WRONG
- Expected Bridge: 192.168.100.1 ✓

**VMs are configured for:**
- Monitor: 192.168.100.8
- Victim: 192.168.100.6
- Attacker: 192.168.100.101

**Result:** VMs cannot reach the host-only bridge (different subnets!)

---

## Solution: Two Options

### Option A: Reconfigure Hypervisor Bridge (Recommended) ⭐

Easier - just one change on the host. VMs already configured correctly.

**For Parallels Desktop:**
1. Open Parallels Control Center or Parallels menu
2. Go to Settings → Network
3. Find Host-Only Networks (usually vnic0)
4. Click Edit
5. Change:
   - Subnet: 192.168.100.0/24
   - Gateway: 192.168.100.1
6. Click OK and Apply

**For VMware Fusion:**
1. Preferences → Network
2. Find Host-Only adapter
3. Click Edit
4. Set:
   - Subnet IP: 192.168.100.0
   - Subnet Mask: 255.255.255.0
5. Apply → Restart VMware

**For VirtualBox:**
1. Preferences → Network → Host-only Networks
2. Select vboxnet0 → Edit
3. In Adapter tab:
   - IPv4 Address: 192.168.100.1
   - IPv4 Mask: 255.255.255.0
4. OK → Restart VirtualBox

**For UTM:**
1. Settings → Network → Host Only
2. Set Bridge IP: 192.168.100.1/24
3. Apply
4. Restart VMs

### Option B: Reconfigure VMs to 192.168.128.x

More work but possible if Option A doesn't work for your hypervisor.

---

## After Fixing

1. **Verify the fix:**
   ```bash
   ping -c 1 192.168.100.8
   ```
   Should show: `64 bytes from 192.168.100.8`

2. **Then run setup:**
   ```bash
   bash scripts/quickstart.sh
   ```

---

## Need Help?

Run the automated fix script:
```bash
bash scripts/fix_network.sh
```

It will guide you through the process for your specific hypervisor.
