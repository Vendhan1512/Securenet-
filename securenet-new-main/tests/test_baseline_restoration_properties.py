"""
Property-based tests for baseline restoration functionality.

**Feature: lan-security-system, Property 17: ARP Cache Recovery**
**Feature: lan-security-system, Property 18: DNS Cache Recovery**
"""

import pytest
from datetime import datetime
from hypothesis import given, strategies as st, settings

from lan_security_system.core.interfaces import AttackType, NetworkBaseline
from lan_security_system.recovery.manager import NetworkRecoveryManager


# Strategies for generating test data
def generate_ip_address():
    """Generate a valid IP address."""
    return st.builds(
        lambda a, b, c, d: f"{a}.{b}.{c}.{d}",
        st.integers(1, 254), st.integers(0, 255), 
        st.integers(0, 255), st.integers(1, 254)
    )

def generate_mac_address():
    """Generate a valid MAC address."""
    return st.builds(
        lambda a, b, c, d, e, f: f"{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}",
        st.integers(0, 255), st.integers(0, 255), st.integers(0, 255),
        st.integers(0, 255), st.integers(0, 255), st.integers(0, 255)
    )

def generate_domain_name():
    """Generate a valid domain name."""
    return st.builds(
        lambda subdomain, domain, tld: f"{subdomain}.{domain}.{tld}",
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=3, max_size=10),
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=3, max_size=10),
        st.sampled_from(["com", "org", "net", "edu", "gov"])
    )

ip_address_strategy = generate_ip_address()
mac_address_strategy = generate_mac_address()
domain_name_strategy = generate_domain_name()

# Strategy for generating ARP table mappings
arp_table_strategy = st.dictionaries(
    keys=ip_address_strategy,
    values=mac_address_strategy,
    min_size=1,
    max_size=10
)

# Strategy for generating DNS cache mappings
dns_cache_strategy = st.dictionaries(
    keys=domain_name_strategy,
    values=ip_address_strategy,
    min_size=1,
    max_size=10
)

# Strategy for generating MAC-to-port mappings
mac_port_strategy = st.dictionaries(
    keys=mac_address_strategy,
    values=st.integers(1, 48),
    min_size=1,
    max_size=10
)


class TestARPCacheRecovery:
    """Test ARP cache recovery property."""
    
    @given(
        arp_table=arp_table_strategy,
        dns_cache=dns_cache_strategy,
        mac_port_mappings=mac_port_strategy
    )
    @settings(max_examples=3)
    def test_arp_cache_recovery_restores_trusted_mappings(self, arp_table, dns_cache, mac_port_mappings):
        """
        **Property 17: ARP Cache Recovery**
        *For any* completed attack mitigation, the recovery manager should restore trusted ARP cache mappings
        **Validates: Requirements 5.1**
        """
        # Create recovery manager in simulation mode
        recovery_manager = NetworkRecoveryManager(simulation_mode=True)
        
        # Initialize simulated state with test data
        recovery_manager._simulated_arp_table = arp_table.copy()
        recovery_manager._simulated_dns_cache = dns_cache.copy()
        recovery_manager._simulated_cam_table = mac_port_mappings.copy()
        
        # Create and save network baseline
        baseline = NetworkBaseline(
            arp_table=arp_table,
            dns_cache=dns_cache,
            mac_port_mappings=mac_port_mappings,
            baseline_timestamp=datetime.now()
        )
        
        # Save baseline to establish trusted mappings
        recovery_manager._baseline = baseline
        recovery_manager._store_trusted_mappings(arp_table, dns_cache)
        
        # Verify trusted mappings were stored
        assert len(recovery_manager._trusted_arp_mappings) == len(arp_table)
        for ip, mac in arp_table.items():
            assert ip in recovery_manager._trusted_arp_mappings
            assert recovery_manager._trusted_arp_mappings[ip].mac_address == mac
        
        # Initiate recovery for ARP spoofing attack
        recovery_result = recovery_manager.initiate_recovery(AttackType.ARP_SPOOFING)
        
        # Verify recovery was successful
        assert recovery_result.success, f"ARP cache recovery should be successful: {recovery_result.error_message}"
        
        # Verify ARP cache restoration was included in restored components
        assert "arp_cache" in recovery_result.restored_components
        assert "arp_mappings" in recovery_result.restored_components
        
        # Verify verification results indicate successful ARP cache restoration
        assert recovery_result.verification_results.get("arp_cache_restored", False), "ARP cache should be marked as restored"
        
        # Verify recovery state was properly tracked
        assert recovery_result.recovery_id in recovery_manager._recovery_states
        recovery_state = recovery_manager._recovery_states[recovery_result.recovery_id]
        assert recovery_state.completed
        assert recovery_state.attack_type == AttackType.ARP_SPOOFING
    
    @given(
        arp_table=arp_table_strategy
    )
    @settings(max_examples=3)
    def test_arp_cache_recovery_handles_empty_baseline(self, arp_table):
        """Test ARP cache recovery when no baseline is available."""
        # Create recovery manager in simulation mode without baseline
        recovery_manager = NetworkRecoveryManager(simulation_mode=True)
        
        # Attempt recovery without baseline
        recovery_result = recovery_manager.initiate_recovery(AttackType.ARP_SPOOFING)
        
        # Recovery should still complete but may have limited effectiveness
        assert recovery_result is not None
        assert recovery_result.recovery_id is not None
        
        # Verify recovery state was created
        assert recovery_result.recovery_id in recovery_manager._recovery_states


class TestDNSCacheRecovery:
    """Test DNS cache recovery property."""
    
    @given(
        arp_table=arp_table_strategy,
        dns_cache=dns_cache_strategy,
        mac_port_mappings=mac_port_strategy
    )
    @settings(max_examples=3)
    def test_dns_cache_recovery_repopulates_legitimate_entries(self, arp_table, dns_cache, mac_port_mappings):
        """
        **Property 18: DNS Cache Recovery**
        *For any* completed DNS spoofing mitigation, the recovery manager should repopulate DNS cache with legitimate entries
        **Validates: Requirements 5.2**
        """
        # Create recovery manager in simulation mode
        recovery_manager = NetworkRecoveryManager(simulation_mode=True)
        
        # Initialize simulated state with test data
        recovery_manager._simulated_arp_table = arp_table.copy()
        recovery_manager._simulated_dns_cache = dns_cache.copy()
        recovery_manager._simulated_cam_table = mac_port_mappings.copy()
        
        # Create and save network baseline
        baseline = NetworkBaseline(
            arp_table=arp_table,
            dns_cache=dns_cache,
            mac_port_mappings=mac_port_mappings,
            baseline_timestamp=datetime.now()
        )
        
        # Save baseline to establish trusted mappings
        recovery_manager._baseline = baseline
        recovery_manager._store_trusted_mappings(arp_table, dns_cache)
        
        # Verify trusted DNS mappings were stored
        assert len(recovery_manager._trusted_dns_mappings) == len(dns_cache)
        for domain, ip in dns_cache.items():
            assert domain in recovery_manager._trusted_dns_mappings
            assert recovery_manager._trusted_dns_mappings[domain] == ip
        
        # Initiate recovery for DNS spoofing attack
        recovery_result = recovery_manager.initiate_recovery(AttackType.DNS_SPOOFING)
        
        # Verify recovery was successful
        assert recovery_result.success, f"DNS cache recovery should be successful: {recovery_result.error_message}"
        
        # Verify DNS cache restoration was included in restored components
        assert "dns_cache" in recovery_result.restored_components
        assert "dns_mappings" in recovery_result.restored_components
        
        # Verify verification results indicate successful DNS cache restoration
        assert recovery_result.verification_results.get("dns_cache_restored", False), "DNS cache should be marked as restored"
        
        # Verify recovery state was properly tracked
        assert recovery_result.recovery_id in recovery_manager._recovery_states
        recovery_state = recovery_manager._recovery_states[recovery_result.recovery_id]
        assert recovery_state.completed
        assert recovery_state.attack_type == AttackType.DNS_SPOOFING
    
    @given(
        dns_cache=dns_cache_strategy
    )
    @settings(max_examples=3)
    def test_dns_cache_recovery_handles_empty_baseline(self, dns_cache):
        """Test DNS cache recovery when no baseline is available."""
        # Create recovery manager in simulation mode without baseline
        recovery_manager = NetworkRecoveryManager(simulation_mode=True)
        
        # Attempt recovery without baseline
        recovery_result = recovery_manager.initiate_recovery(AttackType.DNS_SPOOFING)
        
        # Recovery should still complete but may have limited effectiveness
        assert recovery_result is not None
        assert recovery_result.recovery_id is not None
        
        # Verify recovery state was created
        assert recovery_result.recovery_id in recovery_manager._recovery_states


class TestBaselineManagement:
    """Test network baseline management functionality."""
    
    @given(
        arp_table=arp_table_strategy,
        dns_cache=dns_cache_strategy,
        mac_port_mappings=mac_port_strategy
    )
    @settings(max_examples=3)
    def test_baseline_save_and_restore_consistency(self, arp_table, dns_cache, mac_port_mappings):
        """Test that saved baselines can be consistently restored."""
        # Create recovery manager in simulation mode
        recovery_manager = NetworkRecoveryManager(simulation_mode=True)
        
        # Initialize simulated state with test data
        recovery_manager._simulated_arp_table = arp_table.copy()
        recovery_manager._simulated_dns_cache = dns_cache.copy()
        recovery_manager._simulated_cam_table = mac_port_mappings.copy()
        
        # Create network baseline
        original_baseline = NetworkBaseline(
            arp_table=arp_table,
            dns_cache=dns_cache,
            mac_port_mappings=mac_port_mappings,
            baseline_timestamp=datetime.now()
        )
        
        # Save baseline
        recovery_manager._baseline = original_baseline
        recovery_manager._store_trusted_mappings(arp_table, dns_cache)
        
        # Verify baseline was saved correctly
        assert recovery_manager._baseline is not None
        assert recovery_manager._baseline.arp_table == arp_table
        assert recovery_manager._baseline.dns_cache == dns_cache
        assert recovery_manager._baseline.mac_port_mappings == mac_port_mappings
        
        # Verify trusted mappings were stored
        assert len(recovery_manager._trusted_arp_mappings) == len(arp_table)
        assert len(recovery_manager._trusted_dns_mappings) == len(dns_cache)
        
        # Test recovery for each attack type
        for attack_type in [AttackType.ARP_SPOOFING, AttackType.DNS_SPOOFING, AttackType.MAC_FLOODING]:
            recovery_result = recovery_manager.initiate_recovery(attack_type)
            
            # Verify recovery completed
            assert recovery_result is not None
            assert recovery_result.recovery_id is not None
            
            # Verify recovery state references the correct baseline
            recovery_state = recovery_manager._recovery_states[recovery_result.recovery_id]
            assert recovery_state.baseline_snapshot == original_baseline
    
    @given(
        arp_table=arp_table_strategy,
        dns_cache=dns_cache_strategy
    )
    @settings(max_examples=3)
    def test_trusted_mappings_integrity(self, arp_table, dns_cache):
        """Test that trusted mappings maintain integrity during recovery operations."""
        # Create recovery manager in simulation mode
        recovery_manager = NetworkRecoveryManager(simulation_mode=True)
        
        # Initialize simulated state with test data
        recovery_manager._simulated_arp_table = arp_table.copy()
        recovery_manager._simulated_dns_cache = dns_cache.copy()
        
        # Store trusted mappings
        recovery_manager._store_trusted_mappings(arp_table, dns_cache)
        
        # Verify all ARP mappings are stored correctly
        for ip, mac in arp_table.items():
            assert ip in recovery_manager._trusted_arp_mappings
            trusted_mapping = recovery_manager._trusted_arp_mappings[ip]
            assert trusted_mapping.ip_address == ip
            assert trusted_mapping.mac_address == mac
            assert trusted_mapping.last_verified is not None
            assert isinstance(trusted_mapping.is_gateway, bool)
        
        # Verify all DNS mappings are stored correctly
        for domain, ip in dns_cache.items():
            assert domain in recovery_manager._trusted_dns_mappings
            assert recovery_manager._trusted_dns_mappings[domain] == ip
        
        # Perform multiple recovery operations and verify mappings remain intact
        for _ in range(3):
            recovery_result = recovery_manager.initiate_recovery(AttackType.ARP_SPOOFING)
            
            # Verify trusted mappings are still intact after recovery
            assert len(recovery_manager._trusted_arp_mappings) == len(arp_table)
            assert len(recovery_manager._trusted_dns_mappings) == len(dns_cache)
            
            for ip, mac in arp_table.items():
                assert recovery_manager._trusted_arp_mappings[ip].mac_address == mac


class TestRecoveryStateTracking:
    """Test recovery state tracking and management."""
    
    @given(
        attack_type=st.sampled_from([AttackType.ARP_SPOOFING, AttackType.DNS_SPOOFING, AttackType.MAC_FLOODING]),
        arp_table=arp_table_strategy,
        dns_cache=dns_cache_strategy
    )
    @settings(max_examples=3)
    def test_recovery_state_lifecycle(self, attack_type, arp_table, dns_cache):
        """Test that recovery state is properly tracked throughout the recovery lifecycle."""
        # Create recovery manager in simulation mode
        recovery_manager = NetworkRecoveryManager(simulation_mode=True)
        
        # Initialize simulated state with test data
        recovery_manager._simulated_arp_table = arp_table.copy()
        recovery_manager._simulated_dns_cache = dns_cache.copy()
        
        # Set up baseline
        baseline = NetworkBaseline(
            arp_table=arp_table,
            dns_cache=dns_cache,
            mac_port_mappings={},
            baseline_timestamp=datetime.now()
        )
        recovery_manager._baseline = baseline
        recovery_manager._store_trusted_mappings(arp_table, dns_cache)
        
        # Initiate recovery
        recovery_result = recovery_manager.initiate_recovery(attack_type)
        
        # Verify recovery state was created and tracked
        assert recovery_result.recovery_id in recovery_manager._recovery_states
        recovery_state = recovery_manager._recovery_states[recovery_result.recovery_id]
        
        # Verify recovery state properties
        assert recovery_state.recovery_id == recovery_result.recovery_id
        assert recovery_state.attack_type == attack_type
        assert recovery_state.start_time is not None
        assert recovery_state.baseline_snapshot == baseline
        assert recovery_state.completed
        
        # Verify recovery result properties
        assert recovery_result.success is not None
        assert recovery_result.timestamp is not None
        assert isinstance(recovery_result.restored_components, list)
        assert isinstance(recovery_result.verification_results, dict)
    
    @given(
        arp_table=arp_table_strategy,
        dns_cache=dns_cache_strategy
    )
    @settings(max_examples=3)
    def test_multiple_concurrent_recoveries(self, arp_table, dns_cache):
        """Test that multiple recovery operations can be tracked concurrently."""
        # Create recovery manager in simulation mode
        recovery_manager = NetworkRecoveryManager(simulation_mode=True)
        
        # Initialize simulated state with test data
        recovery_manager._simulated_arp_table = arp_table.copy()
        recovery_manager._simulated_dns_cache = dns_cache.copy()
        
        # Set up baseline
        baseline = NetworkBaseline(
            arp_table=arp_table,
            dns_cache=dns_cache,
            mac_port_mappings={},
            baseline_timestamp=datetime.now()
        )
        recovery_manager._baseline = baseline
        recovery_manager._store_trusted_mappings(arp_table, dns_cache)
        
        # Initiate multiple recoveries
        recovery_results = []
        attack_types = [AttackType.ARP_SPOOFING, AttackType.DNS_SPOOFING, AttackType.MAC_FLOODING]
        
        for attack_type in attack_types:
            result = recovery_manager.initiate_recovery(attack_type)
            recovery_results.append(result)
        
        # Verify all recoveries were tracked
        assert len(recovery_manager._recovery_states) >= len(attack_types)
        
        # Verify each recovery has unique ID and proper state
        recovery_ids = [result.recovery_id for result in recovery_results]
        assert len(set(recovery_ids)) == len(recovery_ids), "All recovery IDs should be unique"
        
        for result in recovery_results:
            assert result.recovery_id in recovery_manager._recovery_states
            recovery_state = recovery_manager._recovery_states[result.recovery_id]
            assert recovery_state.completed