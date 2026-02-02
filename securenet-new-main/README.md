# LAN Security System

Local Network Attack Detection, Mitigation & Recovery System - A comprehensive LAN-level security solution designed to protect enterprise, campus, and SME network environments from internal threats.

## Features

- Real-time attack detection (ARP spoofing, MAC flooding, DNS spoofing)
- Automated mitigation and response
- Network recovery and restoration
- Comprehensive logging and alerting
- Network testbed simulation environment
- Property-based testing validation

## Installation

1. Install system dependencies:
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install python3-dev libpcap-dev

# CentOS/RHEL
sudo yum install python3-devel libpcap-devel
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Install the package:
```bash
pip install -e .
```

## Quick Start

```python
from lan_security_system.config.settings import SystemConfig
from lan_security_system.utils.logging_setup import setup_logging

# Initialize configuration
config = SystemConfig()

# Setup logging
logger = setup_logging(
    log_level=config.get("logging.log_level"),
    log_file=config.get("logging.log_file"),
    console_output=config.get("logging.console_output")
)

logger.info("LAN Security System initialized")
```

## Project Structure

```
lan_security_system/
├── core/           # Core interfaces and base classes
├── detection/      # Detection engine components
├── mitigation/     # Mitigation controller components
├── recovery/       # Recovery manager components
├── logging/        # Logging system components
├── simulation/     # Attack simulation components
├── testbed/        # Network testbed components
├── validation/     # Validation framework components
├── config/         # Configuration management
└── utils/          # Utility functions
```

## Requirements

- Python 3.8+
- libpcap development libraries
- Root privileges for packet capture (or appropriate capabilities)

## License

This project is licensed under the MIT License.