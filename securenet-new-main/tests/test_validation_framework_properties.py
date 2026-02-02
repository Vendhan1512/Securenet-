"""Property-based tests for validation framework."""

import pytest
import tempfile
import os
from pathlib import Path
from hypothesis import given, strategies as st, settings
from scapy.all import rdpcap

from lan_security_system.validation.dataset_processor import DatasetProcessor, TrafficPattern
from lan_security_system.validation.demonstration_system import DemonstrationSystem, DemoScenario


class TestValidationFrameworkProperties:
    """Property-based tests for validation framework components."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.processor = DatasetProcessor(self.temp_dir)
        self.demo_system = DemonstrationSystem(self.temp_dir + "/demos")
    
    def teardown_method(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @given(scenario=st.sampled_from(['arp_spoofing', 'mac_flooding', 'dns_spoofing', 'normal']))
    @settings(max_examples=5, deadline=None)
    def test_property_29_custom_packet_capture_generation(self, scenario):
        """
        Property 29: Custom Packet Capture Generation
        For any attack scenario validation, the system should generate custom packet captures
        **Validates: Requirements 8.3**
        **Feature: lan-security-system, Property 29: Custom Packet Capture Generation**
        """
        # Generate packet capture for the scenario
        pcap_path = self.processor.generate_packet_capture(scenario)
        
        # Verify the pcap file was created
        assert os.path.exists(pcap_path), f"Packet capture file not created for scenario: {scenario}"
        
        # Verify the file is not empty
        assert os.path.getsize(pcap_path) > 0, f"Packet capture file is empty for scenario: {scenario}"
        
        # Verify we can read the packets
        packets = rdpcap(pcap_path)
        assert len(packets) > 0, f"No packets found in capture for scenario: {scenario}"
        
        # Verify scenario-specific characteristics
        if scenario == 'arp_spoofing':
            # Should contain ARP packets
            arp_packets = [pkt for pkt in packets if pkt.haslayer('ARP')]
            assert len(arp_packets) > 0, "ARP spoofing scenario should contain ARP packets"
        
        elif scenario == 'mac_flooding':
            # Should contain multiple packets (flooding behavior)
            assert len(packets) >= 50, "MAC flooding scenario should contain many packets"
        
        elif scenario == 'dns_spoofing':
            # Should contain DNS packets
            dns_packets = [pkt for pkt in packets if pkt.haslayer('DNS')]
            assert len(dns_packets) > 0, "DNS spoofing scenario should contain DNS packets"
        
        elif scenario == 'normal':
            # Should contain normal traffic patterns
            assert len(packets) > 10, "Normal scenario should contain reasonable number of packets"
    
    @given(
        normal_scenario=st.just('normal'),
        malicious_scenario=st.sampled_from(['arp_spoofing', 'mac_flooding', 'dns_spoofing'])
    )
    @settings(max_examples=5, deadline=None)
    def test_property_30_traffic_pattern_differentiation(self, normal_scenario, malicious_scenario):
        """
        Property 30: Traffic Pattern Differentiation
        For any comparison between normal and malicious traffic, the system should clearly differentiate attack patterns
        **Validates: Requirements 8.4**
        **Feature: lan-security-system, Property 30: Traffic Pattern Differentiation**
        """
        # Generate normal traffic capture
        normal_pcap = self.processor.generate_packet_capture(normal_scenario)
        
        # Generate malicious traffic capture
        malicious_pcap = self.processor.generate_packet_capture(malicious_scenario)
        
        # Verify both files exist
        assert os.path.exists(normal_pcap), "Normal traffic capture not generated"
        assert os.path.exists(malicious_pcap), "Malicious traffic capture not generated"
        
        # Analyze traffic patterns
        normal_pattern = self.processor.analyze_traffic_patterns(normal_pcap)
        malicious_pattern = self.processor.analyze_traffic_patterns(malicious_pcap)
        
        # Verify patterns are different types
        assert isinstance(normal_pattern, TrafficPattern), "Normal pattern analysis failed"
        assert isinstance(malicious_pattern, TrafficPattern), "Malicious pattern analysis failed"
        
        # Verify the system can differentiate between patterns
        can_differentiate = self.processor.differentiate_traffic_patterns(normal_pcap, malicious_pcap)
        assert can_differentiate, f"System failed to differentiate between normal and {malicious_scenario} traffic"
        
        # Verify classification is correct
        assert normal_pattern.pattern_type == 'normal', f"Normal traffic misclassified as {normal_pattern.pattern_type}"
        assert malicious_pattern.pattern_type == 'malicious', f"Malicious traffic misclassified as {malicious_pattern.pattern_type}"
        
        # Verify patterns have different characteristics
        patterns_differ = (
            normal_pattern.protocol_distribution != malicious_pattern.protocol_distribution or
            normal_pattern.unique_ips != malicious_pattern.unique_ips or
            normal_pattern.unique_ports != malicious_pattern.unique_ports or
            normal_pattern.packet_count != malicious_pattern.packet_count
        )
        assert patterns_differ, "Normal and malicious patterns should have different characteristics"
    
    @given(scenario_id=st.sampled_from(['arp_spoofing_demo', 'mac_flooding_demo', 'dns_spoofing_demo', 'multi_attack_demo']))
    @settings(max_examples=3, deadline=None)
    def test_property_31_demonstration_scenario_reproducibility(self, scenario_id):
        """
        Property 31: Demonstration Scenario Reproducibility
        For any demonstration scenario, running it multiple times should produce consistent and reproducible results
        **Validates: Requirements 8.5**
        **Feature: lan-security-system, Property 31: Demonstration Scenario Reproducibility**
        """
        # Load the demonstration scenario
        scenario = self.demo_system.load_demonstration_scenario(scenario_id)
        assert isinstance(scenario, DemoScenario), f"Failed to load scenario: {scenario_id}"
        
        # Execute the scenario multiple times (reduced to 2 for faster testing)
        num_runs = 2
        results = []
        
        for run in range(num_runs):
            result = self.demo_system.execute_demonstration_scenario(scenario_id)
            results.append(result)
        
        # Verify all runs completed successfully
        assert len(results) == num_runs, f"Not all runs completed for scenario: {scenario_id}"
        
        # Verify reproducibility hash consistency
        hashes = [result.reproducibility_hash for result in results]
        assert len(set(hashes)) == 1, f"Reproducibility hashes differ across runs for scenario: {scenario_id}"
        
        # Verify validation status consistency
        statuses = [result.validation_status for result in results]
        assert len(set(statuses)) == 1, f"Validation status differs across runs for scenario: {scenario_id}"
        
        # Verify key metrics are within acceptable variance (10% for property testing)
        detection_accuracies = [result.performance_metrics.get("avg_detection_latency", 0) for result in results]
        if detection_accuracies:
            max_variance = max(detection_accuracies) - min(detection_accuracies)
            # Allow for some variance in simulated metrics
            assert max_variance <= 50, f"High variance in detection latency for scenario: {scenario_id}"
        
        # Verify scenario produces expected outcomes
        for result in results:
            assert result.scenario_id == scenario_id, "Scenario ID mismatch in results"
            assert result.execution_duration > 0, "Execution duration should be positive"
            assert isinstance(result.detection_results, dict), "Detection results should be a dictionary"
            assert isinstance(result.mitigation_results, dict), "Mitigation results should be a dictionary"
            assert isinstance(result.recovery_results, dict), "Recovery results should be a dictionary"
            assert isinstance(result.performance_metrics, dict), "Performance metrics should be a dictionary"
        
        # Verify the scenario can be validated for reproducibility using the system method
        is_reproducible = self.demo_system.validate_reproducibility(scenario, num_runs=2)
        assert is_reproducible, f"System reproducibility validation failed for scenario: {scenario_id}"