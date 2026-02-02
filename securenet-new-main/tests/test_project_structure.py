"""
Property-based tests for project structure validation.

**Feature: lan-security-system, Property 1: Project Structure Completeness**
**Validates: Requirements 1.4**
"""

import os
import sys
from pathlib import Path
from hypothesis import given, strategies as st
import pytest

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


class TestProjectStructure:
    """Test project structure completeness and validity."""
    
    def test_required_directories_exist(self):
        """Test that all required project directories exist."""
        required_dirs = [
            "lan_security_system",
            "lan_security_system/core",
            "lan_security_system/detection",
            "lan_security_system/mitigation", 
            "lan_security_system/recovery",
            "lan_security_system/logging",
            "lan_security_system/simulation",
            "lan_security_system/testbed",
            "lan_security_system/validation",
            "lan_security_system/config",
            "lan_security_system/utils",
            "tests"
        ]
        
        for directory in required_dirs:
            dir_path = project_root / directory
            assert dir_path.exists(), f"Required directory {directory} does not exist"
            assert dir_path.is_dir(), f"Path {directory} exists but is not a directory"
    
    def test_required_files_exist(self):
        """Test that all required project files exist."""
        required_files = [
            "lan_security_system/__init__.py",
            "lan_security_system/core/__init__.py",
            "lan_security_system/core/interfaces.py",
            "lan_security_system/detection/__init__.py",
            "lan_security_system/mitigation/__init__.py",
            "lan_security_system/recovery/__init__.py",
            "lan_security_system/logging/__init__.py",
            "lan_security_system/simulation/__init__.py",
            "lan_security_system/testbed/__init__.py",
            "lan_security_system/validation/__init__.py",
            "lan_security_system/config/__init__.py",
            "lan_security_system/config/settings.py",
            "lan_security_system/utils/__init__.py",
            "lan_security_system/utils/logging_setup.py",
            "requirements.txt",
            "setup.py",
            "config.yaml",
            "README.md",
            "tests/__init__.py"
        ]
        
        for file_path in required_files:
            full_path = project_root / file_path
            assert full_path.exists(), f"Required file {file_path} does not exist"
            assert full_path.is_file(), f"Path {file_path} exists but is not a file"
    
    def test_python_modules_importable(self):
        """Test that all Python modules can be imported without errors."""
        importable_modules = [
            "lan_security_system",
            "lan_security_system.core",
            "lan_security_system.core.interfaces",
            "lan_security_system.config.settings",
            "lan_security_system.utils.logging_setup"
        ]
        
        for module_name in importable_modules:
            try:
                __import__(module_name)
            except ImportError as e:
                pytest.fail(f"Failed to import module {module_name}: {e}")
    
    def test_core_interfaces_defined(self):
        """Test that all core interfaces are properly defined."""
        from lan_security_system.core.interfaces import (
            AttackType, DetectionMethod, SecurityAlert, NetworkBaseline,
            DetectionConfig, MitigationResult, RecoveryResult, LogEntry,
            BaseDetector, DetectionEngine, MitigationStrategy, MitigationController,
            RecoveryManager, LoggingSystem, AttackSimulator, NetworkTestbed
        )
        
        # Test enums have expected values
        assert AttackType.ARP_SPOOFING.value == "arp_spoofing"
        assert AttackType.MAC_FLOODING.value == "mac_flooding"
        assert AttackType.DNS_SPOOFING.value == "dns_spoofing"
        
        assert DetectionMethod.SIGNATURE_BASED.value == "signature_based"
        assert DetectionMethod.ANOMALY_BASED.value == "anomaly_based"
        assert DetectionMethod.HYBRID.value == "hybrid"
        
        # Test that dataclasses have required fields
        import inspect
        
        # SecurityAlert should have all required fields
        alert_fields = {field.name for field in SecurityAlert.__dataclass_fields__.values()}
        required_alert_fields = {
            'timestamp', 'alert_id', 'attack_type', 'confidence_score',
            'source_mac', 'source_ip', 'target_mac', 'target_ip',
            'affected_hosts', 'raw_packet_data', 'detection_method'
        }
        assert required_alert_fields.issubset(alert_fields), "SecurityAlert missing required fields"
        
        # Test that abstract base classes have required methods
        detection_methods = {method for method in dir(DetectionEngine) if not method.startswith('_')}
        required_detection_methods = {'start_monitoring', 'register_detector', 'set_alert_callback', 'get_detection_stats'}
        assert required_detection_methods.issubset(detection_methods), "DetectionEngine missing required methods"
    
    @given(st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'))))
    def test_config_system_handles_arbitrary_keys(self, config_key):
        """
        Property test: For any valid configuration key, the config system should handle it gracefully.
        **Feature: lan-security-system, Property 1: Project Structure Completeness**
        **Validates: Requirements 1.4**
        """
        from lan_security_system.config.settings import SystemConfig
        
        config = SystemConfig()
        
        # Test getting non-existent key returns default
        result = config.get(config_key, "default_value")
        assert result == "default_value", f"Config system should return default for non-existent key {config_key}"
        
        # Test setting and getting arbitrary key
        test_value = f"test_value_for_{config_key}"
        config.set(config_key, test_value)
        retrieved_value = config.get(config_key)
        assert retrieved_value == test_value, f"Config system should store and retrieve value for key {config_key}"
    
    @given(st.sampled_from(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]))
    def test_logging_setup_handles_all_levels(self, log_level):
        """
        Property test: For any valid log level, the logging setup should configure correctly.
        **Feature: lan-security-system, Property 1: Project Structure Completeness**
        **Validates: Requirements 1.4**
        """
        from lan_security_system.utils.logging_setup import setup_logging
        
        # Test that logging setup works with any valid log level
        logger = setup_logging(log_level=log_level, console_output=True)
        
        assert logger is not None, f"Logger should be created for log level {log_level}"
        assert logger.name == "lan_security_system", "Logger should have correct name"
        
        # Test that logger level is set correctly
        import logging
        expected_level = getattr(logging, log_level.upper())
        assert logger.level == expected_level, f"Logger level should be set to {expected_level} for {log_level}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])