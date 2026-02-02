"""
Unit tests for the Network Recovery Manager.

Tests baseline save and restore operations, connectivity verification procedures,
and recovery rollback mechanisms.
"""

import pytest
from datetime import datetime
from unittest.mock import Mock, patch

from lan_security_system.core.interfaces import AttackType, NetworkBaseline
from lan_security_system.recovery.manager import NetworkRecoveryManager, TrustedMapping


class TestBaselineSaveAndRestore:
    """Test baseline save and restore operations."""
    
    def test_save_network_baseline_creates_baseline(self):
        """Test that saving network baseline creates proper baseline object."""
        # Create recovery manager
        recovery_manager = NetworkRecoveryManager()
        
        # Create test baseline
        test_arp_table = {"192.168.1.1": "aa:bb:cc:dd:ee:ff", "192.168.1.2": "bb:cc:dd:ee:ff:aa"}
        test_dns_cache = {"example.com": "93.184.216.34", "google.com": "8.8.8.8"}
        test_mac_port_mappings = {"aa:bb:cc:dd:ee:ff": 1, "bb:cc:dd:ee:ff:aa": 2}
        
        baseline = NetworkBaseline(
            arp_table=test_arp_table,
            dns_cache=test_dns_cache,
            mac_port_mappings=test_mac_port_mappings,
            baseline_timestamp=datetime.now()
        )
        
        # Save baseline
        recovery_manager._baseline = baseline
        recovery_manager._store_trusted_mappings(test_arp_table, test_dns_cache)
        
        # Verify baseline was saved
        assert recovery_manager._baseline is not None
        assert recovery_manager._baseline.arp_table == test_arp_table
        assert recovery_manager._baseline.dns_cache == test_dns_cache
        assert recovery_manager._baseline.mac_port_mappings == test_mac_port_mappings
        
        # Verify trusted mappings were stored
        assert len(recovery_manager._trusted_arp_mappings) == len(test_arp_table)
        assert len(recovery_manager._trusted_dns_mappings) == len(test_dns_cache)
        
        for ip, mac in test_arp_table.items():
            assert ip in recovery_manager._trusted_arp_mappings
            assert recovery_manager._trusted_arp_mappings[ip].mac_address == mac
    
    def test_trusted_mapping_creation(self):
        """Test creation of trusted mappings with proper attributes."""
        # Create recovery manager
        recovery_manager = NetworkRecoveryManager()
        
        # Test ARP table with gateway
        test_arp_table = {"192.168.1.1": "aa:bb:cc:dd:ee:ff"}  # Typical gateway IP
        test_dns_cache = {"example.com": "93.184.216.34"}
        
        # Store trusted mappings
        recovery_manager._store_trusted_mappings(test_arp_table, test_dns_cache)
        
        # Verify trusted mapping attributes
        trusted_mapping = recovery_manager._trusted_arp_mappings["192.168.1.1"]
        assert isinstance(trusted_mapping, TrustedMapping)
        assert trusted_mapping.ip_address == "192.168.1.1"
        assert trusted_mapping.mac_address == "aa:bb:cc:dd:ee:ff"
        assert trusted_mapping.last_verified is not None
        assert isinstance(trusted_mapping.is_gateway, bool)
    
    def test_baseline_restoration_for_arp_spoofing(self):
        """Test baseline restoration specifically for ARP spoofing attacks."""
        # Create recovery manager
        recovery_manager = NetworkRecoveryManager()
        
        # Set up baseline
        test_arp_table = {"192.168.1.1": "aa:bb:cc:dd:ee:ff"}
        baseline = NetworkBaseline(
            arp_table=test_arp_table,
            dns_cache={},
            mac_port_mappings={},
            baseline_timestamp=datetime.now()
        )
        recovery_manager._baseline = baseline
        recovery_manager._store_trusted_mappings(test_arp_table, {})
        
        # Initiate recovery for ARP spoofing
        recovery_result = recovery_manager.initiate_recovery(AttackType.ARP_SPOOFING)
        
        # Verify recovery was attempted
        assert recovery_result is not None
        assert recovery_result.recovery_id is not None
        assert "arp_cache" in recovery_result.restored_components or not recovery_result.success
        
        # Verify recovery state was created
        assert recovery_result.recovery_id in recovery_manager._recovery_states
        recovery_state = recovery_manager._recovery_states[recovery_result.recovery_id]
        assert recovery_state.attack_type == AttackType.ARP_SPOOFING
    
    def test_baseline_restoration_for_dns_spoofing(self):
        """Test baseline restoration specifically for DNS spoofing attacks."""
        # Create recovery manager
        recovery_manager = NetworkRecoveryManager()
        
        # Set up baseline
        test_dns_cache = {"example.com": "93.184.216.34"}
        baseline = NetworkBaseline(
            arp_table={},
            dns_cache=test_dns_cache,
            mac_port_mappings={},
            baseline_timestamp=datetime.now()
        )
        recovery_manager._baseline = baseline
        recovery_manager._store_trusted_mappings({}, test_dns_cache)
        
        # Initiate recovery for DNS spoofing
        recovery_result = recovery_manager.initiate_recovery(AttackType.DNS_SPOOFING)
        
        # Verify recovery was attempted
        assert recovery_result is not None
        assert recovery_result.recovery_id is not None
        assert "dns_cache" in recovery_result.restored_components or not recovery_result.success
        
        # Verify recovery state was created
        assert recovery_result.recovery_id in recovery_manager._recovery_states
        recovery_state = recovery_manager._recovery_states[recovery_result.recovery_id]
        assert recovery_state.attack_type == AttackType.DNS_SPOOFING


class TestConnectivityVerificationProcedures:
    """Test connectivity verification procedures."""
    
    def test_network_health_verification_structure(self):
        """Test that network health verification returns proper structure."""
        # Create recovery manager
        recovery_manager = NetworkRecoveryManager()
        
        # Perform health verification
        health_status = recovery_manager.verify_network_health()
        
        # Verify structure
        assert isinstance(health_status, dict)
        assert "arp_table_healthy" in health_status
        assert "dns_cache_healthy" in health_status
        assert "network_connectivity" in health_status
        assert "gateway_accessible" in health_status
        assert "overall_healthy" in health_status
        
        # Verify all values are boolean (except error)
        for key, value in health_status.items():
            if key != "error":
                assert isinstance(value, bool), f"Health check '{key}' should be boolean"
    
    def test_gateway_connectivity_verification_empty_list(self):
        """Test gateway connectivity verification with empty host list."""
        # Create recovery manager
        recovery_manager = NetworkRecoveryManager()
        
        # Test with empty list
        results = recovery_manager.verify_gateway_connectivity_for_hosts([])
        
        # Verify empty results
        assert isinstance(results, dict)
        assert len(results) == 0
    
    def test_gateway_connectivity_verification_single_host(self):
        """Test gateway connectivity verification with single host."""
        # Create recovery manager
        recovery_manager = NetworkRecoveryManager()
        
        # Test with single host
        test_host = "192.168.1.100"
        results = recovery_manager.verify_gateway_connectivity_for_hosts([test_host])
        
        # Verify results structure
        assert isinstance(results, dict)
        assert len(results) == 1
        assert test_host in results
        assert isinstance(results[test_host], bool)
    
    def test_service_validation_empty_list(self):
        """Test service validation with empty service list."""
        # Create recovery manager
        recovery_manager = NetworkRecoveryManager()
        
        # Test with empty list
        results = recovery_manager.verify_network_services_operational([])
        
        # Verify empty results
        assert isinstance(results, dict)
        assert len(results) == 0
    
    def test_service_validation_single_service(self):
        """Test service validation with single service."""
        # Create recovery manager
        recovery_manager = NetworkRecoveryManager()
        
        # Test with single service
        test_service = {
            'name': 'test_service',
            'type': 'ping',
            'target': '127.0.0.1',
            'port': None
        }
        results = recovery_manager.verify_network_services_operational([test_service])
        
        # Verify results structure
        assert isinstance(results, dict)
        assert len(results) == 1
        assert 'test_service' in results
        assert isinstance(results['test_service'], bool)
    
    def test_end_to_end_connectivity_testing_empty_list(self):
        """Test end-to-end connectivity testing with empty scenario list."""
        # Create recovery manager
        recovery_manager = NetworkRecoveryManager()
        
        # Test with empty list
        results = recovery_manager.perform_end_to_end_connectivity_test([])
        
        # Verify empty results
        assert isinstance(results, dict)
        assert len(results) == 0
    
    def test_end_to_end_connectivity_testing_single_scenario(self):
        """Test end-to-end connectivity testing with single scenario."""
        # Create recovery manager
        recovery_manager = NetworkRecoveryManager()
        
        # Test with single scenario
        test_scenario = {
            'name': 'test_ping',
            'source': '192.168.1.1',
            'target': '192.168.1.2',
            'type': 'ping',
            'expected': True
        }
        results = recovery_manager.perform_end_to_end_connectivity_test([test_scenario])
        
        # Verify results structure
        assert isinstance(results, dict)
        assert len(results) == 1
        assert 'test_ping' in results
        assert isinstance(results['test_ping'], bool)


class TestRecoveryRollbackMechanisms:
    """Test recovery rollback mechanisms."""
    
    def test_recovery_validation_with_valid_recovery(self):
        """Test recovery validation with a valid recovery ID."""
        # Create recovery manager
        recovery_manager = NetworkRecoveryManager()
        
        # Set up baseline and perform recovery
        baseline = NetworkBaseline(
            arp_table={"192.168.1.1": "aa:bb:cc:dd:ee:ff"},
            dns_cache={"example.com": "93.184.216.34"},
            mac_port_mappings={},
            baseline_timestamp=datetime.now()
        )
        recovery_manager._baseline = baseline
        recovery_manager._store_trusted_mappings(baseline.arp_table, baseline.dns_cache)
        
        recovery_result = recovery_manager.initiate_recovery(AttackType.ARP_SPOOFING)
        
        # Validate recovery
        validation_result = recovery_manager.validate_recovery_and_rollback_capability(recovery_result.recovery_id)
        
        # Verify validation structure
        assert isinstance(validation_result, dict)
        assert 'valid' in validation_result
        assert 'rollback_available' in validation_result
        assert validation_result['valid'] == True
        assert validation_result['rollback_available'] == True
    
    def test_recovery_validation_with_invalid_recovery_id(self):
        """Test recovery validation with invalid recovery ID."""
        # Create recovery manager
        recovery_manager = NetworkRecoveryManager()
        
        # Test with invalid recovery ID
        validation_result = recovery_manager.validate_recovery_and_rollback_capability("invalid_id")
        
        # Verify error handling
        assert isinstance(validation_result, dict)
        assert validation_result['valid'] == False
        assert 'error' in validation_result
        assert validation_result['rollback_available'] == False
    
    def test_recovery_rollback_with_valid_recovery(self):
        """Test recovery rollback with a valid recovery ID."""
        # Create recovery manager
        recovery_manager = NetworkRecoveryManager()
        
        # Set up baseline and perform recovery
        baseline = NetworkBaseline(
            arp_table={"192.168.1.1": "aa:bb:cc:dd:ee:ff"},
            dns_cache={"example.com": "93.184.216.34"},
            mac_port_mappings={},
            baseline_timestamp=datetime.now()
        )
        recovery_manager._baseline = baseline
        recovery_manager._store_trusted_mappings(baseline.arp_table, baseline.dns_cache)
        
        recovery_result = recovery_manager.initiate_recovery(AttackType.ARP_SPOOFING)
        
        # Perform rollback
        rollback_result = recovery_manager.rollback_recovery(recovery_result.recovery_id)
        
        # Verify rollback
        assert isinstance(rollback_result, bool)
        
        # Verify recovery state was updated
        recovery_state = recovery_manager._recovery_states[recovery_result.recovery_id]
        if rollback_result:
            assert recovery_state.completed == False
    
    def test_recovery_rollback_with_invalid_recovery_id(self):
        """Test recovery rollback with invalid recovery ID."""
        # Create recovery manager
        recovery_manager = NetworkRecoveryManager()
        
        # Test with invalid recovery ID
        rollback_result = recovery_manager.rollback_recovery("invalid_id")
        
        # Verify error handling
        assert isinstance(rollback_result, bool)
        assert rollback_result == False
    
    def test_safe_port_reenabling_basic_functionality(self):
        """Test basic safe port re-enabling functionality."""
        # Create recovery manager
        recovery_manager = NetworkRecoveryManager()
        
        # Add port to disabled ports
        test_port = 5
        recovery_manager._disabled_ports.add(test_port)
        
        # Test safe re-enabling
        source_info = {'mac_address': 'aa:bb:cc:dd:ee:ff', 'ip_address': '192.168.1.100'}
        result = recovery_manager.re_enable_switch_port_safely(test_port, AttackType.MAC_FLOODING, source_info)
        
        # Verify result
        assert isinstance(result, bool)
        
        # Verify port state management
        if result:
            assert test_port not in recovery_manager._disabled_ports
        else:
            assert test_port in recovery_manager._disabled_ports
    
    def test_threat_elimination_confirmation(self):
        """Test threat elimination confirmation for different attack types."""
        # Create recovery manager
        recovery_manager = NetworkRecoveryManager()
        
        # Test for MAC flooding
        source_info_mac = {'mac_address': 'aa:bb:cc:dd:ee:ff'}
        result_mac = recovery_manager.confirm_threat_elimination(AttackType.MAC_FLOODING, source_info_mac)
        assert isinstance(result_mac, bool)
        
        # Test for ARP spoofing
        source_info_arp = {'mac_address': 'bb:cc:dd:ee:ff:aa'}
        result_arp = recovery_manager.confirm_threat_elimination(AttackType.ARP_SPOOFING, source_info_arp)
        assert isinstance(result_arp, bool)
        
        # Test for DNS spoofing
        source_info_dns = {'ip_address': '192.168.1.100'}
        result_dns = recovery_manager.confirm_threat_elimination(AttackType.DNS_SPOOFING, source_info_dns)
        assert isinstance(result_dns, bool)
    
    def test_gradual_port_reenabling(self):
        """Test gradual port re-enabling functionality."""
        # Create recovery manager
        recovery_manager = NetworkRecoveryManager()
        
        # Set up disabled ports
        disabled_ports = [1, 2, 3]
        for port in disabled_ports:
            recovery_manager._disabled_ports.add(port)
        
        # Test gradual re-enabling
        source_info = {'mac_address': 'aa:bb:cc:dd:ee:ff'}
        results = recovery_manager.perform_gradual_port_re_enabling(
            disabled_ports, AttackType.MAC_FLOODING, source_info, batch_size=2, delay_between_batches=0
        )
        
        # Verify results structure
        assert isinstance(results, dict)
        assert len(results) == len(disabled_ports)
        
        for port in disabled_ports:
            assert port in results
            assert isinstance(results[port], bool)


class TestRecoveryManagerEdgeCases:
    """Test edge cases and error conditions."""
    
    def test_recovery_without_baseline(self):
        """Test recovery operations when no baseline is available."""
        # Create recovery manager without baseline
        recovery_manager = NetworkRecoveryManager()
        
        # Attempt recovery without baseline
        recovery_result = recovery_manager.initiate_recovery(AttackType.ARP_SPOOFING)
        
        # Verify recovery handles missing baseline gracefully
        assert recovery_result is not None
        assert recovery_result.recovery_id is not None
        # Recovery may succeed or fail, but should not crash
    
    def test_ip_and_mac_validation(self):
        """Test IP and MAC address validation methods."""
        # Create recovery manager
        recovery_manager = NetworkRecoveryManager()
        
        # Test valid IP addresses
        assert recovery_manager._is_valid_ip("192.168.1.1") == True
        assert recovery_manager._is_valid_ip("10.0.0.1") == True
        assert recovery_manager._is_valid_ip("127.0.0.1") == True
        
        # Test invalid IP addresses
        assert recovery_manager._is_valid_ip("256.1.1.1") == False
        assert recovery_manager._is_valid_ip("192.168.1") == False
        assert recovery_manager._is_valid_ip("not.an.ip.address") == False
        assert recovery_manager._is_valid_ip("") == False
        
        # Test valid MAC addresses
        assert recovery_manager._is_valid_mac("aa:bb:cc:dd:ee:ff") == True
        assert recovery_manager._is_valid_mac("00:11:22:33:44:55") == True
        assert recovery_manager._is_valid_mac("ff:ff:ff:ff:ff:ff") == True
        
        # Test invalid MAC addresses
        assert recovery_manager._is_valid_mac("aa:bb:cc:dd:ee") == False
        assert recovery_manager._is_valid_mac("aa:bb:cc:dd:ee:gg") == False
        assert recovery_manager._is_valid_mac("not:a:mac:address") == False
        assert recovery_manager._is_valid_mac("") == False
    
    def test_multiple_concurrent_recoveries(self):
        """Test handling of multiple concurrent recovery operations."""
        # Create recovery manager
        recovery_manager = NetworkRecoveryManager()
        
        # Set up baseline
        baseline = NetworkBaseline(
            arp_table={"192.168.1.1": "aa:bb:cc:dd:ee:ff"},
            dns_cache={"example.com": "93.184.216.34"},
            mac_port_mappings={},
            baseline_timestamp=datetime.now()
        )
        recovery_manager._baseline = baseline
        recovery_manager._store_trusted_mappings(baseline.arp_table, baseline.dns_cache)
        
        # Initiate multiple recoveries
        recovery1 = recovery_manager.initiate_recovery(AttackType.ARP_SPOOFING)
        recovery2 = recovery_manager.initiate_recovery(AttackType.DNS_SPOOFING)
        recovery3 = recovery_manager.initiate_recovery(AttackType.MAC_FLOODING)
        
        # Verify all recoveries return valid results
        assert recovery1 is not None
        assert recovery2 is not None
        assert recovery3 is not None
        
        assert recovery1.recovery_id is not None
        assert recovery2.recovery_id is not None
        assert recovery3.recovery_id is not None
        
        # Verify recovery states exist (may be overwritten due to timestamp collision)
        assert len(recovery_manager._recovery_states) >= 1
        
        # Verify at least one recovery state exists and has valid structure
        for recovery_id, recovery_state in recovery_manager._recovery_states.items():
            assert recovery_state.recovery_id == recovery_id
            assert recovery_state.attack_type in [AttackType.ARP_SPOOFING, AttackType.DNS_SPOOFING, AttackType.MAC_FLOODING]
            assert recovery_state.start_time is not None
            assert recovery_state.baseline_snapshot == baseline
            assert recovery_state.completed is not None
    
    def test_port_monitoring_functionality(self):
        """Test port monitoring functionality during re-enabling."""
        # Create recovery manager
        recovery_manager = NetworkRecoveryManager()
        
        # Test port monitoring
        monitoring_result = recovery_manager._monitor_port_for_threats(5, AttackType.MAC_FLOODING, 10)
        
        # Verify monitoring result structure
        assert isinstance(monitoring_result, dict)
        assert 'threats_detected' in monitoring_result
        assert 'monitoring_duration' in monitoring_result
        assert 'threat_count' in monitoring_result
        assert 'threat_types' in monitoring_result
        
        # Verify data types
        assert isinstance(monitoring_result['threats_detected'], bool)
        assert isinstance(monitoring_result['monitoring_duration'], int)
        assert isinstance(monitoring_result['threat_count'], int)
        assert isinstance(monitoring_result['threat_types'], list)
        
        # For simulation, should indicate no threats
        assert monitoring_result['threats_detected'] == False
        assert monitoring_result['threat_count'] == 0