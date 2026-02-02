"""
Property-based tests for connectivity verification functionality.

**Feature: lan-security-system, Property 19: Gateway Connectivity Verification**
**Feature: lan-security-system, Property 20: Service Validation After Recovery**
"""

import pytest
from datetime import datetime
from hypothesis import given, strategies as st, settings

from lan_security_system.core.interfaces import AttackType, NetworkBaseline
from lan_security_system.recovery.manager import NetworkRecoveryManager


# Strategies for generating test data
def generate_localhost_ip():
    """Generate localhost IP addresses to avoid network timeouts."""
    return st.sampled_from(["127.0.0.1", "127.0.0.2", "127.0.0.3"])

def generate_test_hostname():
    """Generate test hostnames that resolve locally."""
    return st.sampled_from(["localhost", "test.local", "example.test"])

def generate_service_definition():
    """Generate a service definition for testing with unique names."""
    return st.builds(
        lambda name_suffix, service_type, target, port: {
            'name': f"service_{name_suffix}",  # Ensure unique names
            'type': service_type,
            'target': target,
            'port': port
        },
        name_suffix=st.integers(1, 1000),
        service_type=st.sampled_from(["ping", "tcp", "dns", "http"]),
        target=st.one_of(generate_localhost_ip(), generate_test_hostname()),
        port=st.one_of(st.none(), st.integers(1, 65535))
    )

def generate_connectivity_test_scenario():
    """Generate a connectivity test scenario with unique names."""
    return st.builds(
        lambda name_suffix, source, target, test_type, expected: {
            'name': f"test_{name_suffix}",  # Ensure unique names
            'source': source,
            'target': target,
            'type': test_type,
            'expected': expected
        },
        name_suffix=st.integers(1, 1000),
        source=generate_localhost_ip(),
        target=generate_localhost_ip(),
        test_type=st.sampled_from(["ping", "traceroute", "bandwidth"]),
        expected=st.booleans()
    )

ip_address_strategy = generate_localhost_ip()
hostname_strategy = generate_test_hostname()
service_strategy = generate_service_definition()
test_scenario_strategy = generate_connectivity_test_scenario()


class TestGatewayConnectivityVerification:
    """Test gateway connectivity verification property."""
    
    @given(
        host_ips=st.lists(ip_address_strategy, min_size=1, max_size=2, unique=True)
    )
    @settings(max_examples=3)
    def test_gateway_connectivity_verification_for_all_hosts(self, host_ips):
        """
        **Property 19: Gateway Connectivity Verification**
        *For any* network recovery initiation, the recovery manager should verify gateway connectivity for all legitimate hosts
        **Validates: Requirements 5.3**
        """
        # Create recovery manager in simulation mode to avoid real network calls
        recovery_manager = NetworkRecoveryManager(simulation_mode=True)
        
        # Verify gateway connectivity for all hosts
        connectivity_results = recovery_manager.verify_gateway_connectivity_for_hosts(host_ips)
        
        # Verify results are returned for all hosts
        assert isinstance(connectivity_results, dict), "Gateway connectivity results should be a dictionary"
        assert len(connectivity_results) == len(host_ips), f"Should have results for all {len(host_ips)} hosts"
        
        # Verify all host IPs are included in results
        for host_ip in host_ips:
            assert host_ip in connectivity_results, f"Results should include connectivity status for {host_ip}"
            assert isinstance(connectivity_results[host_ip], bool), f"Connectivity result for {host_ip} should be boolean"
        
        # Verify no extra results are returned
        assert set(connectivity_results.keys()) == set(host_ips), "Results should only include requested hosts"
    
    @given(
        host_ips=st.lists(ip_address_strategy, min_size=1, max_size=1)
    )
    @settings(max_examples=3)
    def test_gateway_connectivity_verification_consistency(self, host_ips):
        """Test that gateway connectivity verification produces consistent results."""
        # Create recovery manager in simulation mode
        recovery_manager = NetworkRecoveryManager(simulation_mode=True)
        
        # Run verification multiple times
        results1 = recovery_manager.verify_gateway_connectivity_for_hosts(host_ips)
        results2 = recovery_manager.verify_gateway_connectivity_for_hosts(host_ips)
        
        # Results should be consistent (same hosts should have same connectivity status)
        assert len(results1) == len(results2), "Both verification runs should return same number of results"
        
        for host_ip in host_ips:
            assert host_ip in results1 and host_ip in results2, f"Both runs should include {host_ip}"
            # In simulation mode, results should be consistent
            assert results1[host_ip] == results2[host_ip], f"Results for {host_ip} should be consistent"
    
    @given(
        host_ips=st.lists(ip_address_strategy, min_size=0, max_size=0)
    )
    @settings(max_examples=3)
    def test_gateway_connectivity_verification_empty_host_list(self, host_ips):
        """Test gateway connectivity verification with empty host list."""
        # Create recovery manager in simulation mode
        recovery_manager = NetworkRecoveryManager(simulation_mode=True)
        
        # Verify connectivity for empty list
        connectivity_results = recovery_manager.verify_gateway_connectivity_for_hosts(host_ips)
        
        # Should return empty results
        assert isinstance(connectivity_results, dict), "Should return dictionary even for empty input"
        assert len(connectivity_results) == 0, "Should return empty results for empty host list"


class TestServiceValidationAfterRecovery:
    """Test service validation after recovery property."""
    
    @given(
        services=st.lists(service_strategy, min_size=1, max_size=2, unique_by=lambda x: x['name'])
    )
    @settings(max_examples=3)
    def test_service_validation_after_recovery_completeness(self, services):
        """
        **Property 20: Service Validation After Recovery**
        *For any* completed recovery process, the system should validate that all legitimate network services are operational
        **Validates: Requirements 5.5**
        """
        # Create recovery manager in simulation mode to avoid real network calls
        recovery_manager = NetworkRecoveryManager(simulation_mode=True)
        
        # Validate network services
        service_results = recovery_manager.verify_network_services_operational(services)
        
        # Verify results are returned for all services
        assert isinstance(service_results, dict), "Service validation results should be a dictionary"
        assert len(service_results) == len(services), f"Should have results for all {len(services)} services"
        
        # Verify all services are included in results (using unique service names)
        service_names = [service['name'] for service in services]
        for service_name in service_names:
            assert service_name in service_results, f"Results should include status for service '{service_name}'"
            assert isinstance(service_results[service_name], bool), f"Service result for '{service_name}' should be boolean"
        
        # Verify no extra results are returned
        assert len(service_results) == len(services), "Should not return results for services not requested"
    
    @given(
        services=st.lists(service_strategy, min_size=1, max_size=1)
    )
    @settings(max_examples=3)
    def test_service_validation_handles_different_service_types(self, services):
        """Test that service validation handles different types of services correctly."""
        # Create recovery manager in simulation mode
        recovery_manager = NetworkRecoveryManager(simulation_mode=True)
        
        # Validate services
        service_results = recovery_manager.verify_network_services_operational(services)
        
        # Verify each service type is handled
        for service in services:
            service_name = service['name']
            service_type = service['type']
            
            assert service_name in service_results, f"Service '{service_name}' should have results"
            
            # Verify the service was processed (result is boolean, not None or error)
            result = service_results[service_name]
            assert isinstance(result, bool), f"Service '{service_name}' of type '{service_type}' should return boolean result"
    
    @given(
        services=st.lists(service_strategy, min_size=0, max_size=0)
    )
    @settings(max_examples=3)
    def test_service_validation_empty_service_list(self, services):
        """Test service validation with empty service list."""
        # Create recovery manager in simulation mode
        recovery_manager = NetworkRecoveryManager(simulation_mode=True)
        
        # Validate empty service list
        service_results = recovery_manager.verify_network_services_operational(services)
        
        # Should return empty results
        assert isinstance(service_results, dict), "Should return dictionary even for empty input"
        assert len(service_results) == 0, "Should return empty results for empty service list"


class TestEndToEndConnectivityTesting:
    """Test end-to-end connectivity testing functionality."""
    
    @given(
        test_scenarios=st.lists(test_scenario_strategy, min_size=1, max_size=2, unique_by=lambda x: x['name'])
    )
    @settings(max_examples=3)
    def test_end_to_end_connectivity_test_completeness(self, test_scenarios):
        """Test that end-to-end connectivity testing covers all scenarios."""
        # Create recovery manager in simulation mode
        recovery_manager = NetworkRecoveryManager(simulation_mode=True)
        
        # Perform end-to-end connectivity tests
        test_results = recovery_manager.perform_end_to_end_connectivity_test(test_scenarios)
        
        # Verify results are returned for all test scenarios
        assert isinstance(test_results, dict), "Test results should be a dictionary"
        assert len(test_results) == len(test_scenarios), f"Should have results for all {len(test_scenarios)} test scenarios"
        
        # Verify all test scenarios are included in results (using unique scenario names)
        scenario_names = [scenario['name'] for scenario in test_scenarios]
        for scenario_name in scenario_names:
            assert scenario_name in test_results, f"Results should include status for test '{scenario_name}'"
            assert isinstance(test_results[scenario_name], bool), f"Test result for '{scenario_name}' should be boolean"
    
    @given(
        test_scenarios=st.lists(test_scenario_strategy, min_size=1, max_size=1)
    )
    @settings(max_examples=3)
    def test_end_to_end_connectivity_test_handles_different_types(self, test_scenarios):
        """Test that end-to-end connectivity testing handles different test types."""
        # Create recovery manager in simulation mode
        recovery_manager = NetworkRecoveryManager(simulation_mode=True)
        
        # Perform connectivity tests
        test_results = recovery_manager.perform_end_to_end_connectivity_test(test_scenarios)
        
        # Verify each test type is handled
        for scenario in test_scenarios:
            scenario_name = scenario['name']
            test_type = scenario['type']
            
            assert scenario_name in test_results, f"Test scenario '{scenario_name}' should have results"
            
            # Verify the test was processed (result is boolean, not None or error)
            result = test_results[scenario_name]
            assert isinstance(result, bool), f"Test '{scenario_name}' of type '{test_type}' should return boolean result"
    
    @given(
        test_scenarios=st.lists(test_scenario_strategy, min_size=0, max_size=0)
    )
    @settings(max_examples=3)
    def test_end_to_end_connectivity_test_empty_scenario_list(self, test_scenarios):
        """Test end-to-end connectivity testing with empty scenario list."""
        # Create recovery manager in simulation mode
        recovery_manager = NetworkRecoveryManager(simulation_mode=True)
        
        # Test with empty scenario list
        test_results = recovery_manager.perform_end_to_end_connectivity_test(test_scenarios)
        
        # Should return empty results
        assert isinstance(test_results, dict), "Should return dictionary even for empty input"
        assert len(test_results) == 0, "Should return empty results for empty scenario list"


class TestConnectivityVerificationIntegration:
    """Test integration of connectivity verification components."""
    
    @given(
        host_ips=st.lists(ip_address_strategy, min_size=1, max_size=1),
        services=st.lists(service_strategy, min_size=1, max_size=1, unique_by=lambda x: x['name']),
        test_scenarios=st.lists(test_scenario_strategy, min_size=1, max_size=1, unique_by=lambda x: x['name'])
    )
    @settings(max_examples=2)
    def test_comprehensive_connectivity_verification(self, host_ips, services, test_scenarios):
        """Test comprehensive connectivity verification across all components."""
        # Create recovery manager in simulation mode
        recovery_manager = NetworkRecoveryManager(simulation_mode=True)
        
        # Perform all types of connectivity verification
        gateway_results = recovery_manager.verify_gateway_connectivity_for_hosts(host_ips)
        service_results = recovery_manager.verify_network_services_operational(services)
        e2e_results = recovery_manager.perform_end_to_end_connectivity_test(test_scenarios)
        
        # Verify all verification types return appropriate results
        assert isinstance(gateway_results, dict), "Gateway connectivity results should be dictionary"
        assert isinstance(service_results, dict), "Service validation results should be dictionary"
        assert isinstance(e2e_results, dict), "End-to-end test results should be dictionary"
        
        # Verify result counts match input counts
        assert len(gateway_results) == len(host_ips), "Gateway results should match host count"
        assert len(service_results) == len(services), "Service results should match service count"
        assert len(e2e_results) == len(test_scenarios), "E2E results should match scenario count"
        
        # Verify all results are boolean values
        for result in gateway_results.values():
            assert isinstance(result, bool), "Gateway connectivity results should be boolean"
        
        for result in service_results.values():
            assert isinstance(result, bool), "Service validation results should be boolean"
        
        for result in e2e_results.values():
            assert isinstance(result, bool), "End-to-end test results should be boolean"
    
    @given(
        host_ips=st.lists(ip_address_strategy, min_size=1, max_size=1)
    )
    @settings(max_examples=2)
    def test_network_health_verification_integration(self, host_ips):
        """Test that network health verification integrates with connectivity verification."""
        # Create recovery manager in simulation mode
        recovery_manager = NetworkRecoveryManager(simulation_mode=True)
        
        # Perform network health verification
        health_status = recovery_manager.verify_network_health()
        
        # Verify health status includes connectivity-related checks
        assert isinstance(health_status, dict), "Health status should be dictionary"
        assert "network_connectivity" in health_status, "Health status should include network connectivity check"
        assert "gateway_accessible" in health_status, "Health status should include gateway accessibility check"
        assert "overall_healthy" in health_status, "Health status should include overall health assessment"
        
        # Verify all health checks return boolean values
        for key, value in health_status.items():
            if key != "error":  # Error key might contain string message
                assert isinstance(value, bool), f"Health check '{key}' should return boolean value"
    
    @given(
        attack_type=st.sampled_from([AttackType.ARP_SPOOFING, AttackType.DNS_SPOOFING])
    )
    @settings(max_examples=2)
    def test_connectivity_verification_after_recovery(self, attack_type):
        """Test that connectivity verification works after recovery operations."""
        # Create recovery manager in simulation mode
        recovery_manager = NetworkRecoveryManager(simulation_mode=True)
        
        # Set up minimal baseline for recovery
        baseline = NetworkBaseline(
            arp_table={"192.168.1.1": "aa:bb:cc:dd:ee:ff"},
            dns_cache={"example.com": "93.184.216.34"},
            mac_port_mappings={"aa:bb:cc:dd:ee:ff": 1},
            baseline_timestamp=datetime.now()
        )
        recovery_manager._baseline = baseline
        recovery_manager._store_trusted_mappings(baseline.arp_table, baseline.dns_cache)
        
        # Perform recovery
        recovery_result = recovery_manager.initiate_recovery(attack_type)
        
        # Verify recovery completed
        assert recovery_result is not None, "Recovery should return result"
        assert recovery_result.recovery_id is not None, "Recovery should have ID"
        
        # Perform connectivity verification after recovery
        health_status = recovery_manager.verify_network_health()
        
        # Verify connectivity verification works after recovery
        assert isinstance(health_status, dict), "Health verification should work after recovery"
        assert "overall_healthy" in health_status, "Should include overall health status"
        
        # Test specific connectivity functions
        gateway_results = recovery_manager.verify_gateway_connectivity_for_hosts(["127.0.0.1"])
        assert isinstance(gateway_results, dict), "Gateway connectivity should work after recovery"
        assert len(gateway_results) == 1, "Should return result for requested host"