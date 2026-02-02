"""
Configuration settings for the LAN Security System.
"""

import logging
import os
from pathlib import Path
from typing import Dict, Any


class SystemConfig:
    """System configuration management."""
    
    def __init__(self, config_file: str = None):
        self.config_file = config_file or "config.yaml"
        self.config_data = self._load_default_config()
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration settings."""
        return {
            "system": {
                "simulation_mode": True,
                "health_check_interval": 30,
                "max_component_errors": 5,
                "component_restart_delay": 10
            },
            "detection": {
                "arp_rate_threshold": 10,
                "mac_learning_threshold": 50,
                "cam_table_threshold": 0.9,
                "dns_ttl_variance_threshold": 300,
                "detection_window_size": 60,
                "detection_latency_target": 100,
                "false_positive_threshold": 0.05,
                "dns_safe_mode": True
            },
            "performance": {
                "max_monitored_hosts": 100,
                "cpu_utilization_threshold": 0.8,
                "detection_accuracy_threshold": 0.95,
                "mitigation_response_time": 200,
                "recovery_time_limit": 30,
                "max_memory_mb": 1000,
                "processing_threads": 4,
                "queue_maxsize": 10000
            },
            "logging": {
                "log_level": "INFO",
                "log_file": "lan_security.log",
                "log_directory": "logs",
                "max_file_size": 10485760,
                "max_log_size": "10MB",
                "backup_count": 5,
                "console_output": True
            },
            "network": {
                "default_interface": "eth0",
                "capture_buffer_size": 65536,
                "packet_timeout": 1000
            },
            "alerting": {
                "console_alerts": True,
                "email_alerts": False,
                "email_smtp_server": "",
                "email_smtp_port": 587,
                "email_username": "",
                "email_password": "",
                "email_recipients": []
            }
        }
    
    def get(self, key: str, default=None):
        """Get configuration value by key."""
        keys = key.split('.')
        value = self.config_data
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value by key."""
        keys = key.split('.')
        config = self.config_data
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        config[keys[-1]] = value