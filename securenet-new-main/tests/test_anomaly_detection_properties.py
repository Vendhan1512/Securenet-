"""
Property-based tests for anomaly-based detection components.

**Feature: lan-security-system, Property 9: ARP Rate Anomaly Detection**
**Feature: lan-security-system, Property 10: CAM Table Overflow Detection**
"""

import pytest
from hypothesis import given, strategies as st, settings
from datetime import datetime, timedelta
from scapy.all import Ether, ARP
import time

from lan_security_system.detection.anomaly_detectors import (
    ARPRateAnomalyDetector, CAMTableOverflowDetector, DNSAnomalyDetector
)
from lan_security_system.core.interfaces import NetworkBaseline, DetectionConfig, AttackType


# Strategy for generating IP addresses
ip_address = st.integers(min_value=1, max_value=254).map(
    lambda x: f"192.168.1.{x}"
)

# Strategy for generating MAC addresses
mac_address = st.text(
    alphabet='0123456789abcdef',
    min_size=12,
    max_size=12
).map(lambda x: ':'.join([x[i:i+2] for i in range(0, 12, 2)]))


class TestARPRateAnomalyDetection:
    """Property tests for ARP rate anomaly detection."""
    
    @given(
        sender_ip=ip_address,
        arp_rate=st.integers(min_value=11, max_value=50)  # Above threshold of 10
    )
    @settings(max_examples=3, deadline=1000)  # Increase deadline for time simulation
    def test_arp_rate_anomaly_detection(self, sender_ip, arp_rate):
        """
        Property 9: ARP Rate Anomaly Detection
        For any network interface generating ARP requests above the configured rate threshold,
        the detection engine should trigger anomaly alerts.
        **Validates: Requirements 3.4**
        """
        config = DetectionConfig(arp_rate_threshold=10, detection_window_size=1)  # 1 second window for testing
        detector = ARPRateAnomalyDetector(config)
        
        alert_generated = False
        
        # Pre-populate the tracking with timestamps to simulate high rate
        current_time = datetime.now()
        packet_interval = 1.0 / arp_rate  # Time between packets to achieve desired rate
        
        # Pre-populate with timestamps to simulate the desired rate
        for i in range(arp_rate - 1):  # Leave one for the actual detect call
            simulated_time = current_time - timedelta(seconds=i * packet_interval)
            detector.arp_request_tracking[sender_ip].append(simulated_time)
        
        # Now send the final packet that should trigger detection
        packet = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=1,  # ARP request
            hwsrc="00:11:22:33:44:55",
            psrc=sender_ip,
            hwdst="00:00:00:00:00:00",
            pdst="192.168.1.1"
        )
        
        alert = detector.detect(bytes(packet))
        
        if alert is not None:
            alert_generated = True
            assert alert.attack_type == AttackType.ARP_SPOOFING
            assert alert.source_ip == sender_ip
        
        # Should detect anomaly when rate exceeds threshold
        assert alert_generated, f"Should detect ARP rate anomaly with {arp_rate} requests per second"
    
    @given(
        sender_ip=ip_address,
        arp_rate=st.integers(min_value=1, max_value=10)  # Below or at threshold
    )
    @settings(max_examples=3, deadline=1000)
    def test_normal_arp_rate_not_flagged(self, sender_ip, arp_rate):
        """
        Test that normal ARP rates below threshold are not flagged.
        """
        config = DetectionConfig(arp_rate_threshold=10, detection_window_size=10)  # Shorter window for testing
        detector = ARPRateAnomalyDetector(config)
        
        # Simulate packets arriving over time at normal rate
        packet_interval = 1.0 / max(arp_rate, 1)  # Avoid division by zero
        
        for i in range(arp_rate):
            packet = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=1,  # ARP request
                hwsrc="00:11:22:33:44:55",
                psrc=sender_ip,
                hwdst="00:00:00:00:00:00",
                pdst="192.168.1.1"
            )
            
            # Simulate time passage for normal rate
            current_time = datetime.now()
            if i > 0:
                simulated_time = current_time - timedelta(seconds=(arp_rate - i - 1) * packet_interval)
                detector.arp_request_tracking[sender_ip].append(simulated_time)
            
            alert = detector.detect(bytes(packet))
            
            # Should not generate alert for normal rates
            assert alert is None, f"Should not flag normal ARP rate of {arp_rate} requests per second"
    
    @given(
        sender_ip=ip_address,
        baseline_rate=st.floats(min_value=1.0, max_value=5.0),
        current_rate=st.integers(min_value=16, max_value=30)  # 3x+ baseline
    )
    @settings(max_examples=3, deadline=1000)
    def test_baseline_deviation_detection(self, sender_ip, baseline_rate, current_rate):
        """
        Test detection when current rate significantly exceeds baseline.
        """
        config = DetectionConfig(arp_rate_threshold=50, detection_window_size=1)  # High threshold, 1 second window
        detector = ARPRateAnomalyDetector(config)
        
        # Set up baseline
        baseline = NetworkBaseline(
            arp_table={sender_ip: "00:11:22:33:44:55"},
            dns_cache={},
            mac_port_mappings={},
            baseline_timestamp=datetime.now()
        )
        detector.update_baseline(baseline)
        detector.baseline_arp_rates[sender_ip] = baseline_rate
        
        alert_generated = False
        
        # Pre-populate the tracking with timestamps to simulate high rate
        current_time = datetime.now()
        packet_interval = 1.0 / current_rate
        
        # Pre-populate with timestamps to simulate the desired rate
        for i in range(current_rate - 1):  # Leave one for the actual detect call
            simulated_time = current_time - timedelta(seconds=i * packet_interval)
            detector.arp_request_tracking[sender_ip].append(simulated_time)
        
        # Now send the final packet that should trigger detection
        packet = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=1,  # ARP request
            hwsrc="00:11:22:33:44:55",
            psrc=sender_ip,
            hwdst="00:00:00:00:00:00",
            pdst="192.168.1.1"
        )
        
        alert = detector.detect(bytes(packet))
        
        if alert is not None:
            alert_generated = True
            assert alert.attack_type == AttackType.ARP_SPOOFING
        
        # Should detect when rate is significantly above baseline
        if current_rate > baseline_rate * 3:
            assert alert_generated, f"Should detect rate {current_rate} above baseline {baseline_rate}"


class TestCAMTableOverflowDetection:
    """Property tests for CAM table overflow detection."""
    
    @given(
        mac_count=st.integers(min_value=7373, max_value=8192)  # Near/at 90% of 8192
    )
    @settings(max_examples=3, deadline=2000)  # Increase deadline for processing many MACs
    def test_cam_table_overflow_detection(self, mac_count):
        """
        Property 10: CAM Table Overflow Detection
        For any CAM table reaching 90% or higher utilization, the detection engine
        should detect potential MAC flooding attacks.
        **Validates: Requirements 3.5**
        """
        config = DetectionConfig(cam_table_threshold=0.9, detection_window_size=60)
        detector = CAMTableOverflowDetector(config)
        
        alert_generated = False
        
        # Pre-populate CAM table to near threshold to speed up test
        base_count = int(mac_count * 0.8)  # Start at 80% to reduce processing time
        current_time = datetime.now()
        for i in range(base_count):
            mac = f"aa:bb:cc:{i//65536:02x}:{(i//256)%256:02x}:{i%256:02x}"
            detector.simulated_cam_table[mac] = current_time
        
        # Generate remaining unique MAC addresses to reach target
        remaining_count = mac_count - base_count
        for i in range(remaining_count):
            mac_index = base_count + i
            mac = f"00:11:22:{mac_index//65536:02x}:{(mac_index//256)%256:02x}:{mac_index%256:02x}"
            packet = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
            
            alert = detector.detect(bytes(packet))
            
            if alert is not None:
                alert_generated = True
                assert alert.attack_type == AttackType.MAC_FLOODING
                break
        
        # Should detect overflow when utilization >= 90%
        utilization = mac_count / 8192
        if utilization >= 0.9:
            assert alert_generated, f"Should detect CAM table overflow at {utilization:.2%} utilization"
    
    @given(
        mac_count=st.integers(min_value=1, max_value=4096)  # Below 50% utilization
    )
    @settings(max_examples=3, deadline=1000)
    def test_normal_cam_utilization_not_flagged(self, mac_count):
        """
        Test that normal CAM table utilization is not flagged.
        """
        config = DetectionConfig(cam_table_threshold=0.9, detection_window_size=60)
        detector = CAMTableOverflowDetector(config)
        
        # Generate MAC addresses for normal utilization
        for i in range(min(mac_count, 1000)):  # Limit to 1000 for performance
            mac = f"00:11:22:{i//65536:02x}:{(i//256)%256:02x}:{i%256:02x}"
            packet = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
            
            alert = detector.detect(bytes(packet))
            
            # Should not generate alert for normal utilization
            current_utilization = (i + 1) / 8192
            if current_utilization < 0.9:
                assert alert is None, f"Should not flag normal CAM utilization of {current_utilization:.2%}"
    
    @given(
        learning_rate=st.integers(min_value=51, max_value=100)  # Above threshold of 50
    )
    @settings(max_examples=3, deadline=1000)
    def test_high_mac_learning_rate_detection(self, learning_rate):
        """
        Test detection of high MAC learning rates indicating flooding.
        """
        config = DetectionConfig(
            mac_learning_threshold=50,
            detection_window_size=1,  # 1 second window for testing
            cam_table_threshold=0.95  # High threshold to focus on learning rate
        )
        detector = CAMTableOverflowDetector(config)
        
        alert_generated = False
        
        # Pre-populate the MAC learning rate tracking to simulate high rate
        current_time = datetime.now()
        packet_interval = 1.0 / learning_rate  # Time between MACs to achieve desired rate
        
        # Pre-populate with timestamps to simulate the desired learning rate
        for i in range(learning_rate - 1):  # Leave one for the actual detect call
            simulated_time = current_time - timedelta(seconds=i * packet_interval)
            detector.mac_learning_rate.append(simulated_time)
        
        # Now send the final packet with a new MAC that should trigger detection
        mac = f"aa:bb:cc:00:00:{learning_rate:02x}"
        packet = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
        
        alert = detector.detect(bytes(packet))
        
        if alert is not None:
            alert_generated = True
            assert alert.attack_type == AttackType.MAC_FLOODING
        
        # Should detect high learning rate
        assert alert_generated, f"Should detect high MAC learning rate of {learning_rate} MACs per second"


class TestDNSAnomalyDetection:
    """Property tests for DNS anomaly detection."""
    
    @given(
        domain=st.text(alphabet='abcdefghijklmnopqrstuvwxyz', min_size=3, max_size=10).map(lambda x: f"{x}.com"),
        ttl_variance=st.integers(min_value=301, max_value=1000)  # Above threshold of 300
    )
    @settings(max_examples=3, deadline=1000)
    def test_dns_ttl_anomaly_detection(self, domain, ttl_variance):
        """
        Test detection of abnormal DNS TTL values.
        """
        config = DetectionConfig(dns_ttl_variance_threshold=300, detection_window_size=60)
        detector = DNSAnomalyDetector(config)
        
        # Set baseline TTL - this is crucial for the detector to work
        baseline = NetworkBaseline(
            arp_table={},
            dns_cache={domain: "192.168.1.100"},
            mac_port_mappings={},
            baseline_timestamp=datetime.now()
        )
        detector.update_baseline(baseline)
        
        # Verify baseline was set correctly
        assert domain in detector.baseline_dns_ttls, f"Baseline not set for domain {domain}"
        
        # Create DNS response with abnormal TTL using proper construction
        from scapy.layers.inet import IP, UDP
        from scapy.layers.dns import DNS, DNSQR, DNSRR
        
        baseline_ttl = detector.baseline_dns_ttls[domain]  # Use the actual baseline TTL (3600)
        abnormal_ttl = baseline_ttl + ttl_variance  # Add variance to baseline
        
        # Construct DNS packet properly
        dns_query = DNSQR(qname=domain)
        dns_answer = DNSRR(rrname=domain, rdata="192.168.1.100", ttl=abnormal_ttl)
        
        packet = (
            Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") /
            IP(src="8.8.8.8", dst="192.168.1.100", proto=17) /  # UDP protocol
            UDP(sport=53, dport=53) /  # DNS uses UDP port 53
            DNS(
                id=12345,
                qr=1,  # DNS response
                aa=1,
                ancount=1,  # Explicitly set answer count
                qd=dns_query,
                an=dns_answer
            )
        )
        
        alert = detector.detect(bytes(packet))
        
        # Should detect TTL anomaly when variance exceeds threshold
        assert alert is not None, f"Should detect DNS TTL anomaly with variance {ttl_variance} (TTL: {abnormal_ttl} vs baseline: {baseline_ttl})"
        assert alert.attack_type == AttackType.DNS_SPOOFING
        assert domain in alert.affected_hosts
    
    @given(
        domain=st.text(alphabet='abcdefghijklmnopqrstuvwxyz', min_size=3, max_size=10).map(lambda x: f"{x}.com"),
        ip1=ip_address,
        ip2=ip_address,
        ip3=ip_address
    )
    @settings(max_examples=3, deadline=1000)
    def test_rapid_ip_changes_detection(self, domain, ip1, ip2, ip3):
        """
        Test detection of rapid IP changes for the same domain.
        """
        # Ensure IPs are different for meaningful test
        ips = [ip1, ip2, ip3]
        unique_ips = list(set(ips))
        if len(unique_ips) < 2:
            # Skip test if not enough unique IPs
            return
            
        config = DetectionConfig(dns_ttl_variance_threshold=1000, detection_window_size=60)
        detector = DNSAnomalyDetector(config)
        
        from scapy.layers.inet import IP, UDP
        from scapy.layers.dns import DNS, DNSQR, DNSRR
        
        # Send multiple DNS responses with different IPs in sequence
        alert_generated = False
        
        # Send at least 3 responses to trigger the rapid change detection
        test_ips = unique_ips[:2] + [unique_ips[0]]  # Ensure we have at least 3 responses with 2 unique IPs
        
        for i, ip in enumerate(test_ips):
            # Construct DNS packet properly
            dns_query = DNSQR(qname=domain)
            dns_answer = DNSRR(rrname=domain, rdata=ip, ttl=300)
            
            packet = (
                Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") /
                IP(src="8.8.8.8", dst="192.168.1.100", proto=17) /  # UDP protocol
                UDP(sport=53, dport=53) /  # DNS uses UDP port 53
                DNS(
                    id=12345 + i,
                    qr=1,  # DNS response
                    aa=1,
                    ancount=1,  # Explicitly set answer count
                    qd=dns_query,
                    an=dns_answer
                )
            )
            
            alert = detector.detect(bytes(packet))
            
            if alert is not None:
                alert_generated = True
                assert alert.attack_type == AttackType.DNS_SPOOFING
                assert domain in alert.affected_hosts
                break
        
        # Should detect rapid IP changes when we have multiple unique IPs in recent responses
        if len(unique_ips) >= 2:
            assert alert_generated, f"Should detect rapid IP changes for domain {domain} with IPs: {unique_ips}"
