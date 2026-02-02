"""
Property-based tests for cache management functionality.

**Feature: lan-security-system, Property 14: ARP Cache Reset Effectiveness**
**Feature: lan-security-system, Property 15: DNS Cache Flushing Effectiveness**
"""

import pytest
from datetime import datetime
from hypothesis import given, strategies as st

from lan_security_system.core.interfaces import AttackType, NetworkBaseline
from lan_security_system.mitigation.cache_manager import CacheManager


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


class TestARPCacheResetEffectiveness:
    """Test ARP cache reset effectiveness property."""
    
    @given(
        arp_table=arp_table_strategy,
        poisoned_ips=st.lists(ip_address_strategy, min_size=1, max_size=5)
    )
    def test_arp_cache_reset_removes_poisoned_entries(self, arp_table, poisoned_ips):
        """
        **Property 14: ARP Cache Reset Effectiveness**
        *For any* poisoned ARP cache entries, the mitigation controller should reset them to remove malicious mappings
        **Validates: Requirements 4.5**
        """
        # Create cache manager
        cache_manager = CacheManager()
        
        # Create network baseline with ARP table
        baseline = NetworkBaseline(
            arp_table=arp_table,
            dns_cache={},
            mac_port_mappings={},
            baseline_timestamp=datetime.now()
        )
        
        # Save the baseline
        cache_manager.save_network_baseline(baseline)
        
        # Mark some IPs as poisoned (use IPs that exist in the ARP table)
        valid_poisoned_ips = [ip for ip in poisoned_ips if ip in arp_table]
        if not valid_poisoned_ips:
            # If no valid poisoned IPs, use one from the ARP table
            valid_poisoned_ips = [list(arp_table.keys())[0]]
        
        for ip in valid_poisoned_ips:
            cache_manager.mark_arp_entry_poisoned(ip)
        
        # Verify IPs are marked as poisoned
        # Note: poisoned_arp_entries is a set, so duplicates are automatically removed
        expected_poisoned_count = len(set(valid_poisoned_ips))
        assert len(cache_manager.poisoned_arp_entries) >= expected_poisoned_count
        for ip in set(valid_poisoned_ips):  # Use set to remove duplicates
            assert ip in cache_manager.poisoned_arp_entries
        
        # Reset ARP cache
        result = cache_manager.reset_arp_cache()
        
        # Verify reset was successful
        assert result, "ARP cache reset should be successful"
        
        # Verify poisoned entries are cleared
        for ip in set(valid_poisoned_ips):  # Use set to remove duplicates
            assert ip not in cache_manager.poisoned_arp_entries, f"IP {ip} should be removed from poisoned entries"
    
    @given(
        arp_table=arp_table_strategy,
        target_ip=ip_address_strategy
    )
    def test_arp_cache_reset_specific_ip(self, arp_table, target_ip):
        """Test that ARP cache reset can target specific IP addresses."""
        # Create cache manager
        cache_manager = CacheManager()
        
        # Create network baseline
        baseline = NetworkBaseline(
            arp_table=arp_table,
            dns_cache={},
            mac_port_mappings={},
            baseline_timestamp=datetime.now()
        )
        
        cache_manager.save_network_baseline(baseline)
        
        # Mark the target IP as poisoned
        cache_manager.mark_arp_entry_poisoned(target_ip)
        
        # Reset only the specific IP
        result = cache_manager.reset_arp_cache([target_ip])
        
        # Verify reset was successful
        assert result, f"ARP cache reset for {target_ip} should be successful"
        
        # Verify the specific IP is no longer marked as poisoned
        assert target_ip not in cache_manager.poisoned_arp_entries


class TestDNSCacheFlushingEffectiveness:
    """Test DNS cache flushing effectiveness property."""
    
    @given(
        dns_cache=dns_cache_strategy,
        poisoned_domains=st.lists(domain_name_strategy, min_size=1, max_size=5)
    )
    def test_dns_cache_flush_removes_malicious_entries(self, dns_cache, poisoned_domains):
        """
        **Property 15: DNS Cache Flushing Effectiveness**
        *For any* malicious DNS cache entries, the mitigation controller should flush them to eliminate false mappings
        **Validates: Requirements 4.6**
        """
        # Create cache manager
        cache_manager = CacheManager()
        
        # Create network baseline with DNS cache
        baseline = NetworkBaseline(
            arp_table={},
            dns_cache=dns_cache,
            mac_port_mappings={},
            baseline_timestamp=datetime.now()
        )
        
        # Save the baseline
        cache_manager.save_network_baseline(baseline)
        
        # Mark some domains as poisoned (use domains that exist in the DNS cache)
        valid_poisoned_domains = list(set([domain for domain in poisoned_domains if domain in dns_cache]))
        if not valid_poisoned_domains:
            # If no valid poisoned domains, use one from the DNS cache
            valid_poisoned_domains = [list(dns_cache.keys())[0]]
        
        for domain in valid_poisoned_domains:
            cache_manager.mark_dns_entry_poisoned(domain)
        
        # Verify domains are marked as poisoned (use set to handle duplicates)
        assert len(cache_manager.poisoned_dns_entries) >= len(valid_poisoned_domains)
        for domain in valid_poisoned_domains:
            assert domain in cache_manager.poisoned_dns_entries
        
        # Flush DNS cache for specific domains
        result = cache_manager.flush_dns_cache(valid_poisoned_domains)
        
        # Verify flush was successful
        assert result, "DNS cache flush should be successful"
        
        # Verify poisoned entries are cleared
        for domain in valid_poisoned_domains:
            assert domain not in cache_manager.poisoned_dns_entries, f"Domain {domain} should be removed from poisoned entries"
    
    @given(dns_cache=dns_cache_strategy)
    def test_dns_cache_flush_entire_cache(self, dns_cache):
        """Test that DNS cache can flush the entire cache."""
        # Create cache manager
        cache_manager = CacheManager()
        
        # Create network baseline
        baseline = NetworkBaseline(
            arp_table={},
            dns_cache=dns_cache,
            mac_port_mappings={},
            baseline_timestamp=datetime.now()
        )
        
        cache_manager.save_network_baseline(baseline)
        
        # Mark all domains as poisoned
        for domain in dns_cache.keys():
            cache_manager.mark_dns_entry_poisoned(domain)
        
        # Flush entire DNS cache
        result = cache_manager.flush_dns_cache()
        
        # Verify flush was successful
        assert result, "Entire DNS cache flush should be successful"
        
        # Verify all poisoned entries are cleared
        assert len(cache_manager.poisoned_dns_entries) == 0, "All poisoned DNS entries should be cleared"


class TestNetworkStateCleanup:
    """Test comprehensive network state cleanup."""
    
    @given(
        attack_type=st.sampled_from([AttackType.ARP_SPOOFING, AttackType.DNS_SPOOFING, AttackType.MAC_FLOODING]),
        arp_table=arp_table_strategy,
        dns_cache=dns_cache_strategy
    )
    def test_network_state_cleanup_by_attack_type(self, attack_type, arp_table, dns_cache):
        """Test that network state cleanup is performed appropriately for each attack type."""
        # Create cache manager
        cache_manager = CacheManager()
        
        # Create network baseline
        baseline = NetworkBaseline(
            arp_table=arp_table,
            dns_cache=dns_cache,
            mac_port_mappings={},
            baseline_timestamp=datetime.now()
        )
        
        cache_manager.save_network_baseline(baseline)
        
        # Mark some entries as poisoned based on attack type
        if attack_type == AttackType.ARP_SPOOFING and arp_table:
            test_ip = list(arp_table.keys())[0]
            cache_manager.mark_arp_entry_poisoned(test_ip)
        elif attack_type == AttackType.DNS_SPOOFING and dns_cache:
            test_domain = list(dns_cache.keys())[0]
            cache_manager.mark_dns_entry_poisoned(test_domain)
        
        # Perform cleanup
        result = cache_manager.cleanup_network_state(attack_type)
        
        # Verify cleanup was successful
        assert result, f"Network state cleanup for {attack_type.value} should be successful"
        
        # Verify appropriate cleanup was performed
        if attack_type == AttackType.ARP_SPOOFING:
            # ARP entries should be cleaned
            assert len(cache_manager.poisoned_arp_entries) == 0, "ARP poisoned entries should be cleared"
        elif attack_type == AttackType.DNS_SPOOFING:
            # DNS entries should be cleaned
            assert len(cache_manager.poisoned_dns_entries) == 0, "DNS poisoned entries should be cleared"
        # MAC_FLOODING cleanup is simulated and always returns True


class TestCacheManagerStatus:
    """Test cache manager status reporting."""
    
    @given(
        arp_table=arp_table_strategy,
        dns_cache=dns_cache_strategy
    )
    def test_cache_status_reporting(self, arp_table, dns_cache):
        """Test that cache manager correctly reports status information."""
        # Create cache manager
        cache_manager = CacheManager()
        
        # Create network baseline
        baseline = NetworkBaseline(
            arp_table=arp_table,
            dns_cache=dns_cache,
            mac_port_mappings={},
            baseline_timestamp=datetime.now()
        )
        
        cache_manager.save_network_baseline(baseline)
        
        # Get initial status
        status = cache_manager.get_cache_status()
        
        # Verify status reflects the baseline
        assert status["original_arp_entries"] == len(arp_table)
        assert status["original_dns_entries"] == len(dns_cache)
        assert status["poisoned_arp_entries"] == 0
        assert status["poisoned_dns_entries"] == 0
        
        # Mark some entries as poisoned
        if arp_table:
            test_ip = list(arp_table.keys())[0]
            cache_manager.mark_arp_entry_poisoned(test_ip)
        
        if dns_cache:
            test_domain = list(dns_cache.keys())[0]
            cache_manager.mark_dns_entry_poisoned(test_domain)
        
        # Get updated status
        updated_status = cache_manager.get_cache_status()
        
        # Verify status reflects the poisoned entries
        if arp_table:
            assert updated_status["poisoned_arp_entries"] >= 1
        if dns_cache:
            assert updated_status["poisoned_dns_entries"] >= 1