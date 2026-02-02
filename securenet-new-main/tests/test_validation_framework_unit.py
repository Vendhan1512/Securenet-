"""Unit tests for validation framework components."""

import pytest
import tempfile
import os
import json
from pathlib import Path
from unittest.mock import patch, MagicMock
import pandas as pd

from lan_security_system.validation.dataset_processor import DatasetProcessor, ValidationDataset, TrafficPattern
from lan_security_system.validation.demonstration_system import DemonstrationSystem, DemoScenario, DemoResult


class TestDatasetProcessor:
    """Unit tests for DatasetProcessor class."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.processor = DatasetProcessor(self.temp_dir)
    
    def teardown_method(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_dataset_loading_cic_ids_2017(self):
        """Test loading CIC-IDS-2017 dataset."""
        # Create mock CSV file
        dataset_dir = Path(self.temp_dir) / "cic-ids-2017"
        dataset_dir.mkdir()
        
        # Create sample CSV data
        sample_data = pd.DataFrame({
            'Label': ['BENIGN', 'BENIGN', 'DoS', 'PortScan', 'BENIGN'],
            'Flow Duration': [1000, 2000, 3000, 4000, 5000],
            'Total Fwd Packets': [10, 20, 30, 40, 50]
        })
        csv_file = dataset_dir / "sample.csv"
        sample_data.to_csv(csv_file, index=False)
        
        # Test loading
        dataset = self.processor.load_ids_dataset('CIC-IDS-2017', str(dataset_dir))
        
        assert isinstance(dataset, ValidationDataset)
        assert dataset.dataset_name == 'CIC-IDS-2017'
        assert dataset.normal_traffic_samples == 3  # 3 BENIGN samples
        assert dataset.malicious_traffic_samples == 2  # 2 attack samples
        assert 'DoS' in dataset.attack_types
        assert 'PortScan' in dataset.attack_types
        assert dataset.ground_truth_labels['BENIGN'] == 'normal'
        assert dataset.ground_truth_labels['DoS'] == 'malicious'
    
    def test_dataset_loading_unsw_nb15(self):
        """Test loading UNSW-NB15 dataset."""
        # Create mock CSV file
        dataset_dir = Path(self.temp_dir) / "unsw-nb15"
        dataset_dir.mkdir()
        
        # Create sample CSV data
        sample_data = pd.DataFrame({
            'attack_cat': ['normal', None, 'Fuzzers', 'Analysis', 'normal'],
            'dur': [1.0, 2.0, 3.0, 4.0, 5.0],
            'proto': ['tcp', 'udp', 'tcp', 'tcp', 'udp']
        })
        csv_file = dataset_dir / "sample.csv"
        sample_data.to_csv(csv_file, index=False)
        
        # Test loading
        dataset = self.processor.load_ids_dataset('UNSW-NB15', str(dataset_dir))
        
        assert isinstance(dataset, ValidationDataset)
        assert dataset.dataset_name == 'UNSW-NB15'
        assert dataset.normal_traffic_samples == 2  # 2 normal (NaN is not counted in pandas value_counts by default)
        assert dataset.malicious_traffic_samples == 2  # 2 attack samples
        assert 'Fuzzers' in dataset.attack_types
        assert 'Analysis' in dataset.attack_types
    
    def test_unsupported_dataset(self):
        """Test handling of unsupported dataset."""
        with pytest.raises(ValueError, match="Unsupported dataset"):
            self.processor.load_ids_dataset('UNKNOWN-DATASET')
    
    def test_missing_dataset_path(self):
        """Test handling of missing dataset path."""
        with pytest.raises(FileNotFoundError):
            self.processor.load_ids_dataset('CIC-IDS-2017', '/nonexistent/path')
    
    def test_packet_capture_generation_scenarios(self):
        """Test packet capture generation for different scenarios."""
        scenarios = ['arp_spoofing', 'mac_flooding', 'dns_spoofing', 'normal']
        
        for scenario in scenarios:
            pcap_path = self.processor.generate_packet_capture(scenario)
            
            # Verify file exists and is not empty
            assert os.path.exists(pcap_path)
            assert os.path.getsize(pcap_path) > 0
            
            # Verify file extension
            assert pcap_path.endswith('.pcap')
    
    def test_invalid_scenario(self):
        """Test handling of invalid scenario."""
        with pytest.raises(ValueError, match="Unsupported scenario"):
            self.processor.generate_packet_capture('invalid_scenario')
    
    def test_traffic_pattern_analysis(self):
        """Test traffic pattern analysis."""
        # Generate a test packet capture
        pcap_path = self.processor.generate_packet_capture('normal')
        
        # Analyze the traffic pattern
        pattern = self.processor.analyze_traffic_patterns(pcap_path)
        
        assert isinstance(pattern, TrafficPattern)
        assert pattern.packet_count > 0
        assert pattern.unique_ips > 0
        assert isinstance(pattern.protocol_distribution, dict)
        assert isinstance(pattern.temporal_features, dict)
        assert isinstance(pattern.statistical_features, dict)
        assert pattern.pattern_type in ['normal', 'malicious']
    
    def test_traffic_pattern_differentiation(self):
        """Test traffic pattern differentiation."""
        # Generate normal and malicious traffic
        normal_pcap = self.processor.generate_packet_capture('normal')
        malicious_pcap = self.processor.generate_packet_capture('arp_spoofing')
        
        # Test differentiation
        can_differentiate = self.processor.differentiate_traffic_patterns(normal_pcap, malicious_pcap)
        assert isinstance(can_differentiate, bool)
    
    def test_classification_heuristics(self):
        """Test traffic classification heuristics."""
        # Test ARP flooding detection
        protocol_dist = {'ARP': 40, 'TCP': 60}
        result = self.processor._classify_traffic_pattern(protocol_dist, 10, 20, 100)
        assert result == 'malicious'  # High ARP ratio
        
        # Test MAC flooding detection
        protocol_dist = {'TCP': 100}
        result = self.processor._classify_traffic_pattern(protocol_dist, 50, 20, 100)
        assert result == 'malicious'  # High IP diversity in large capture
        
        # Test normal traffic
        protocol_dist = {'TCP': 80, 'UDP': 20}
        result = self.processor._classify_traffic_pattern(protocol_dist, 5, 10, 100)
        assert result == 'normal'


class TestDemonstrationSystem:
    """Unit tests for DemonstrationSystem class."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.demo_system = DemonstrationSystem(self.temp_dir)
    
    def teardown_method(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_demonstration_system_initialization(self):
        """Test demonstration system initialization."""
        # Verify directories are created
        assert self.demo_system.demo_dir.exists()
        assert self.demo_system.scenarios_dir.exists()
        assert self.demo_system.results_dir.exists()
        
        # Verify default scenarios are created
        scenarios = self.demo_system.list_available_scenarios()
        expected_scenarios = ['arp_spoofing_demo', 'mac_flooding_demo', 'dns_spoofing_demo', 'multi_attack_demo']
        for scenario in expected_scenarios:
            assert scenario in scenarios
    
    def test_create_demonstration_scenario(self):
        """Test creating a custom demonstration scenario."""
        scenario = self.demo_system.create_demonstration_scenario(
            scenario_id="test_scenario",
            scenario_name="Test Scenario",
            description="A test scenario",
            attack_types=["test_attack"],
            network_config={"hosts": ["test_host"]},
            expected_outcomes={"detection": True},
            validation_criteria=["Test criterion"]
        )
        
        assert isinstance(scenario, DemoScenario)
        assert scenario.scenario_id == "test_scenario"
        assert scenario.scenario_name == "Test Scenario"
        assert "test_attack" in scenario.attack_types
        assert len(scenario.reproducibility_hash) == 16  # SHA256 truncated to 16 chars
    
    def test_load_demonstration_scenario(self):
        """Test loading demonstration scenario."""
        # Load a default scenario
        scenario = self.demo_system.load_demonstration_scenario("arp_spoofing_demo")
        
        assert isinstance(scenario, DemoScenario)
        assert scenario.scenario_id == "arp_spoofing_demo"
        assert "arp_spoofing" in scenario.attack_types
        assert len(scenario.validation_criteria) > 0
    
    def test_load_nonexistent_scenario(self):
        """Test loading nonexistent scenario."""
        with pytest.raises(FileNotFoundError):
            self.demo_system.load_demonstration_scenario("nonexistent_scenario")
    
    def test_execute_demonstration_scenario(self):
        """Test executing demonstration scenario."""
        result = self.demo_system.execute_demonstration_scenario("arp_spoofing_demo")
        
        assert isinstance(result, DemoResult)
        assert result.scenario_id == "arp_spoofing_demo"
        assert result.execution_duration > 0
        assert isinstance(result.detection_results, dict)
        assert isinstance(result.mitigation_results, dict)
        assert isinstance(result.recovery_results, dict)
        assert isinstance(result.performance_metrics, dict)
        assert result.validation_status in ["PASSED", "FAILED"] or result.validation_status.startswith("FAILED:")
    
    def test_scenario_validation(self):
        """Test scenario validation logic."""
        scenario = self.demo_system.load_demonstration_scenario("arp_spoofing_demo")
        
        # Test successful validation
        detection_results = {"attacks_detected": 1, "detection_times": {"arp_spoofing": 50}}
        mitigation_results = {"actions_taken": 1, "response_times": {"arp_spoofing": 150}}
        recovery_results = {"connectivity_verified": True}
        
        status = self.demo_system._validate_demonstration_results(
            scenario, detection_results, mitigation_results, recovery_results
        )
        assert status == "PASSED"
        
        # Test failed validation (detection time exceeded)
        detection_results = {"attacks_detected": 1, "detection_times": {"arp_spoofing": 150}}
        status = self.demo_system._validate_demonstration_results(
            scenario, detection_results, mitigation_results, recovery_results
        )
        assert status.startswith("FAILED:")
    
    def test_reproducibility_validation(self):
        """Test reproducibility validation."""
        scenario = self.demo_system.load_demonstration_scenario("arp_spoofing_demo")
        
        # Test with minimal runs for unit testing
        is_reproducible = self.demo_system.validate_reproducibility(scenario, num_runs=2)
        assert isinstance(is_reproducible, bool)
    
    def test_scenario_summary(self):
        """Test getting scenario summary."""
        summary = self.demo_system.get_scenario_summary("arp_spoofing_demo")
        
        assert isinstance(summary, dict)
        assert summary["scenario_id"] == "arp_spoofing_demo"
        assert "scenario_name" in summary
        assert "description" in summary
        assert "attack_types" in summary
        assert "reproducibility_hash" in summary
    
    def test_demonstration_report_generation(self):
        """Test demonstration report generation."""
        # Execute a scenario to get results
        result = self.demo_system.execute_demonstration_scenario("arp_spoofing_demo")
        
        # Generate report
        report = self.demo_system.generate_demonstration_report("arp_spoofing_demo", result)
        
        assert isinstance(report, str)
        assert "Demonstration Report" in report
        assert "arp_spoofing_demo" in report
        assert "Detection Results" in report
        assert "Mitigation Results" in report
        assert "Recovery Results" in report
        assert "Performance Metrics" in report
    
    def test_metrics_collection(self):
        """Test performance metrics collection."""
        scenario = self.demo_system.load_demonstration_scenario("arp_spoofing_demo")
        metrics = self.demo_system._collect_performance_metrics(scenario, None)
        
        assert isinstance(metrics, dict)
        required_metrics = [
            "avg_detection_latency", "avg_mitigation_response_time", "recovery_time",
            "detection_accuracy", "false_positive_rate", "false_negative_rate",
            "cpu_utilization", "memory_usage", "throughput"
        ]
        
        for metric in required_metrics:
            assert metric in metrics
            assert isinstance(metrics[metric], (int, float))
    
    def test_simulation_phases(self):
        """Test individual simulation phases."""
        scenario = self.demo_system.load_demonstration_scenario("multi_attack_demo")
        
        # Test detection phase
        detection_results = self.demo_system._simulate_detection_phase(scenario, None)
        assert isinstance(detection_results, dict)
        assert "attacks_detected" in detection_results
        assert "detection_times" in detection_results
        
        # Test mitigation phase
        mitigation_results = self.demo_system._simulate_mitigation_phase(scenario, None)
        assert isinstance(mitigation_results, dict)
        assert "mitigation_actions" in mitigation_results
        assert "response_times" in mitigation_results
        
        # Test recovery phase
        recovery_results = self.demo_system._simulate_recovery_phase(scenario, None)
        assert isinstance(recovery_results, dict)
        assert "recovery_actions" in recovery_results
        assert "recovery_time" in recovery_results
    
    def test_reproducibility_hash_generation(self):
        """Test reproducibility hash generation."""
        data1 = {"key": "value", "list": [1, 2, 3]}
        data2 = {"key": "value", "list": [1, 2, 3]}
        data3 = {"key": "different", "list": [1, 2, 3]}
        
        hash1 = self.demo_system._generate_reproducibility_hash(data1)
        hash2 = self.demo_system._generate_reproducibility_hash(data2)
        hash3 = self.demo_system._generate_reproducibility_hash(data3)
        
        assert hash1 == hash2  # Same data should produce same hash
        assert hash1 != hash3  # Different data should produce different hash
        assert len(hash1) == 16  # Hash should be 16 characters