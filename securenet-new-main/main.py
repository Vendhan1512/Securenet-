#!/usr/bin/env python3
"""
Main entry point for the LAN Security System.

This script provides the primary command-line interface for running the
LAN Security System in various modes (daemon, interactive, status check).
"""

import sys
from pathlib import Path

# Ensure current directory is in Python path (important for sudo execution)
sys.path.insert(0, str(Path(__file__).parent))

from lan_security_system.core.system_manager import main

if __name__ == "__main__":
    exit(main())