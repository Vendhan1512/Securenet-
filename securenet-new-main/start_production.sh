ach#!/bin/bash

# Production LAN Security System Startup Script
# This script starts the security system in production mode

echo "🚀 Starting LAN Security System - Production Mode"
echo "=================================================="

# Check if running as root (required for network monitoring)
if [ "$EUID" -ne 0 ]; then
    echo "❌ Error: This script must be run as root for network monitoring"
    echo "   Please run: sudo $0"
    exit 1
fi

# Set production environment variables
export PRODUCTION_MODE=true
export LOG_LEVEL=WARNING
export SIEM_API_KEY="your-siem-api-key-here"

# Create log directory if it doesn't exist
mkdir -p /var/log/security
chown $SUDO_USER:$SUDO_USER /var/log/security

# Check if network interface exists
INTERFACE=${1:-eth0}
if ! ip link show $INTERFACE > /dev/null 2>&1; then
    echo "❌ Error: Network interface '$INTERFACE' not found"
    echo "   Available interfaces:"
    ip link show | grep -E "^[0-9]+:" | cut -d: -f2 | tr -d ' '
    echo "   Usage: $0 <interface>"
    exit 1
fi

echo "✅ Network interface '$INTERFACE' found"
echo "✅ Production environment configured"
echo "✅ Starting security monitoring..."

# Start the production system
python3 production_main.py \
    --daemon \
    --interface $INTERFACE \
    --config production_config.yaml \
    --log-level WARNING

echo "🛡️  LAN Security System is now protecting your network!"
echo "📊 Monitor logs: tail -f /var/log/security/production_security.log"
echo "🔍 Check status: python3 production_main.py --status --interface $INTERFACE"