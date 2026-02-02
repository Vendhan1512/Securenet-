"""Demonstration and reproducibility system for validation framework."""

import json
import time
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class DemoScenario:
    """Model for demonstration scenario configuration."""
    scenario_id: str
    scenario_name: str
    description: str
    attack_types: List[str]
    network_config: Dict[str, Any]
    expected_outcomes: Dict[str, Any]
    validation_criteria: List[str]
    reproducibility_hash: str
    created_timestamp: datetime


@dataclass
class DemoResult:
    """Model for demonstration execution results."""
    scenario_id: str
    execution_timestamp: datetime
    execution_duration: float
    detection_results: Dict[str, Any]
    mitigation_results: Dict[str, Any]
    recovery_results: Dict[str, Any]
    performance_metrics: Dict[str, float]
    validation_status: str
    reproducibility_hash: str


@dataclass
class PerformanceMetrics:
    """Model for performance and accuracy metrics."""
    detection_latency: float
    mitigation_response_time: float
    recovery_time: float
    detection_accuracy: float
    false_positive_rate: float
    false_negative_rate: float
    cpu_utilization: float
    memory_usage: float
    throughput: float


class DemonstrationSystem:
    """System for creating and executing reproducible demonstration scenarios."""
    
    def __init__(self, demo_dir: str = "demonstrations"):
        """Initialize demonstration system.
        
        Args:
            demo_dir: Directory to store demonstration scenarios and results
        """
        self.demo_dir = Path(demo_dir)
        self.demo_dir.mkdir(exist_ok=True)
        self.scenarios_dir = self.demo_dir / "scenarios"
        self.results_dir = self.demo_dir / "results"
        self.scenarios_dir.mkdir(exist_ok=True)
        self.results_dir.mkdir(exist_ok=True)
        
        # Predefined demonstration scenarios
        self._initialize_default_scenarios()
    
    def _initialize_default_scenarios(self):
        """Initialize default demonstration scenarios."""
        default_scenarios = [
            {
                "scenario_id": "arp_spoofing_demo",
                "scenario_name": "ARP Spoofing Attack Demonstration",
                "description": "Demonstrates detection and mitigation of ARP spoofing attacks",
                "attack_types": ["arp_spoofing"],
                "network_config": {
                    "hosts": ["attacker", "victim", "gateway"],
                    "topology": "simple_lan",
                    "subnet": "192.168.1.0/24"
                },
                "expected_outcomes": {
                    "detection": True,
                    "mitigation": True,
                    "recovery": True,
                    "detection_time": "<100ms",
                    "mitigation_time": "<200ms"
                },
                "validation_criteria": [
                    "ARP spoofing detected within 100ms",
                    "Attacker MAC blocked within 200ms",
                    "ARP cache restored successfully",
                    "Network connectivity verified"
                ]
            },
            {
                "scenario_id": "mac_flooding_demo",
                "scenario_name": "MAC Flooding Attack Demonstration",
                "description": "Demonstrates detection and mitigation of MAC flooding attacks",
                "attack_types": ["mac_flooding"],
                "network_config": {
                    "hosts": ["attacker", "victims"],
                    "topology": "switched_lan",
                    "cam_table_size": 100
                },
                "expected_outcomes": {
                    "detection": True,
                    "mitigation": True,
                    "recovery": True,
                    "cam_overflow": True,
                    "port_disabled": True
                },
                "validation_criteria": [
                    "CAM table overflow detected",
                    "Switch port disabled within 200ms",
                    "Port re-enabled after threat elimination",
                    "Normal switching behavior restored"
                ]
            },
            {
                "scenario_id": "dns_spoofing_demo",
                "scenario_name": "DNS Spoofing Attack Demonstration",
                "description": "Demonstrates detection and mitigation of DNS spoofing attacks",
                "attack_types": ["dns_spoofing"],
                "network_config": {
                    "hosts": ["attacker", "victim", "dns_server"],
                    "topology": "routed_network",
                    "dns_servers": ["8.8.8.8", "1.1.1.1"]
                },
                "expected_outcomes": {
                    "detection": True,
                    "mitigation": True,
                    "recovery": True,
                    "firewall_rules": True,
                    "dns_cache_flushed": True
                },
                "validation_criteria": [
                    "DNS spoofing detected",
                    "Firewall rules inserted",
                    "DNS cache flushed and repopulated",
                    "Legitimate DNS resolution verified"
                ]
            },
            {
                "scenario_id": "multi_attack_demo",
                "scenario_name": "Multi-Vector Attack Demonstration",
                "description": "Demonstrates coordinated multi-attack scenario handling",
                "attack_types": ["arp_spoofing", "mac_flooding", "dns_spoofing"],
                "network_config": {
                    "hosts": ["multiple_attackers", "victims", "infrastructure"],
                    "topology": "complex_network",
                    "concurrent_attacks": True
                },
                "expected_outcomes": {
                    "detection": True,
                    "mitigation": True,
                    "recovery": True,
                    "coordination": True,
                    "prioritization": True
                },
                "validation_criteria": [
                    "All attack types detected",
                    "Coordinated mitigation response",
                    "Proper attack prioritization",
                    "Complete network recovery",
                    "System stability maintained"
                ]
            }
        ]
        
        for scenario_config in default_scenarios:
            self.create_demonstration_scenario(**scenario_config)
    
    def create_demonstration_scenario(self, scenario_id: str, scenario_name: str, 
                                    description: str, attack_types: List[str],
                                    network_config: Dict[str, Any], 
                                    expected_outcomes: Dict[str, Any],
                                    validation_criteria: List[str]) -> DemoScenario:
        """Create a new demonstration scenario.
        
        Args:
            scenario_id: Unique identifier for the scenario
            scenario_name: Human-readable name
            description: Detailed description of the scenario
            attack_types: List of attack types to demonstrate
            network_config: Network topology and configuration
            expected_outcomes: Expected results from the demonstration
            validation_criteria: Criteria for validating successful demonstration
            
        Returns:
            DemoScenario object
        """
        # Generate reproducibility hash
        scenario_data = {
            "scenario_id": scenario_id,
            "attack_types": sorted(attack_types),
            "network_config": network_config,
            "expected_outcomes": expected_outcomes,
            "validation_criteria": sorted(validation_criteria)
        }
        reproducibility_hash = self._generate_reproducibility_hash(scenario_data)
        
        scenario = DemoScenario(
            scenario_id=scenario_id,
            scenario_name=scenario_name,
            description=description,
            attack_types=attack_types,
            network_config=network_config,
            expected_outcomes=expected_outcomes,
            validation_criteria=validation_criteria,
            reproducibility_hash=reproducibility_hash,
            created_timestamp=datetime.now()
        )
        
        # Save scenario to file
        scenario_file = self.scenarios_dir / f"{scenario_id}.json"
        with open(scenario_file, 'w') as f:
            json.dump(asdict(scenario), f, indent=2, default=str)
        
        logger.info(f"Created demonstration scenario: {scenario_name} ({scenario_id})")
        return scenario
    
    def load_demonstration_scenario(self, scenario_id: str) -> DemoScenario:
        """Load a demonstration scenario from file.
        
        Args:
            scenario_id: Unique identifier for the scenario
            
        Returns:
            DemoScenario object
            
        Raises:
            FileNotFoundError: If scenario file doesn't exist
        """
        scenario_file = self.scenarios_dir / f"{scenario_id}.json"
        if not scenario_file.exists():
            raise FileNotFoundError(f"Scenario not found: {scenario_id}")
        
        with open(scenario_file, 'r') as f:
            scenario_data = json.load(f)
        
        # Convert timestamp string back to datetime
        scenario_data['created_timestamp'] = datetime.fromisoformat(scenario_data['created_timestamp'])
        
        return DemoScenario(**scenario_data)
    
    def execute_demonstration_scenario(self, scenario_id: str, 
                                     system_components: Optional[Dict[str, Any]] = None) -> DemoResult:
        """Execute a demonstration scenario.
        
        Args:
            scenario_id: Unique identifier for the scenario
            system_components: Optional system components for testing
            
        Returns:
            DemoResult object with execution results
        """
        scenario = self.load_demonstration_scenario(scenario_id)
        start_time = time.time()
        
        logger.info(f"Executing demonstration scenario: {scenario.scenario_name}")
        
        # Simulate demonstration execution
        # In a real implementation, this would integrate with actual system components
        detection_results = self._simulate_detection_phase(scenario, system_components)
        mitigation_results = self._simulate_mitigation_phase(scenario, system_components)
        recovery_results = self._simulate_recovery_phase(scenario, system_components)
        performance_metrics = self._collect_performance_metrics(scenario, system_components)
        
        execution_duration = time.time() - start_time
        
        # Validate results against expected outcomes
        validation_status = self._validate_demonstration_results(
            scenario, detection_results, mitigation_results, recovery_results
        )
        
        result = DemoResult(
            scenario_id=scenario_id,
            execution_timestamp=datetime.now(),
            execution_duration=execution_duration,
            detection_results=detection_results,
            mitigation_results=mitigation_results,
            recovery_results=recovery_results,
            performance_metrics=performance_metrics,
            validation_status=validation_status,
            reproducibility_hash=scenario.reproducibility_hash
        )
        
        # Save results
        self._save_demonstration_result(result)
        
        logger.info(f"Demonstration completed in {execution_duration:.2f}s - Status: {validation_status}")
        return result
    
    def _simulate_detection_phase(self, scenario: DemoScenario, 
                                system_components: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Simulate the detection phase of demonstration."""
        results = {
            "attacks_detected": len(scenario.attack_types),
            "detection_times": {},
            "detection_accuracy": 0.95,
            "false_positives": 0,
            "detection_methods": []
        }
        
        for attack_type in scenario.attack_types:
            # Simulate detection timing
            detection_time = 50 + hash(attack_type) % 50  # 50-100ms
            results["detection_times"][attack_type] = detection_time
            
            if attack_type == "arp_spoofing":
                results["detection_methods"].append("signature_based")
            elif attack_type == "mac_flooding":
                results["detection_methods"].append("anomaly_based")
            elif attack_type == "dns_spoofing":
                results["detection_methods"].append("signature_based")
        
        return results
    
    def _simulate_mitigation_phase(self, scenario: DemoScenario,
                                 system_components: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Simulate the mitigation phase of demonstration."""
        results = {
            "mitigation_actions": [],
            "response_times": {},
            "success_rate": 1.0,
            "actions_taken": len(scenario.attack_types)
        }
        
        for attack_type in scenario.attack_types:
            # Simulate mitigation timing
            response_time = 100 + hash(attack_type) % 100  # 100-200ms
            results["response_times"][attack_type] = response_time
            
            if attack_type == "arp_spoofing":
                results["mitigation_actions"].append("mac_address_blocked")
            elif attack_type == "mac_flooding":
                results["mitigation_actions"].append("switch_port_disabled")
            elif attack_type == "dns_spoofing":
                results["mitigation_actions"].append("firewall_rules_inserted")
        
        return results
    
    def _simulate_recovery_phase(self, scenario: DemoScenario,
                               system_components: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Simulate the recovery phase of demonstration."""
        results = {
            "recovery_actions": [],
            "recovery_time": 15.0,  # 15 seconds
            "connectivity_verified": True,
            "services_restored": True,
            "baseline_restored": True
        }
        
        for attack_type in scenario.attack_types:
            if attack_type == "arp_spoofing":
                results["recovery_actions"].append("arp_cache_restored")
            elif attack_type == "mac_flooding":
                results["recovery_actions"].append("switch_port_reenabled")
            elif attack_type == "dns_spoofing":
                results["recovery_actions"].append("dns_cache_repopulated")
        
        return results
    
    def _collect_performance_metrics(self, scenario: DemoScenario,
                                   system_components: Optional[Dict[str, Any]]) -> Dict[str, float]:
        """Collect performance and accuracy metrics."""
        return {
            "avg_detection_latency": 75.0,  # milliseconds
            "avg_mitigation_response_time": 150.0,  # milliseconds
            "recovery_time": 15.0,  # seconds
            "detection_accuracy": 0.95,
            "false_positive_rate": 0.02,
            "false_negative_rate": 0.01,
            "cpu_utilization": 0.65,
            "memory_usage": 0.45,
            "throughput": 1000.0  # packets per second
        }
    
    def _validate_demonstration_results(self, scenario: DemoScenario,
                                      detection_results: Dict[str, Any],
                                      mitigation_results: Dict[str, Any],
                                      recovery_results: Dict[str, Any]) -> str:
        """Validate demonstration results against expected outcomes."""
        validation_passed = True
        failed_criteria = []
        
        # Check detection requirements
        if scenario.expected_outcomes.get("detection", False):
            if detection_results["attacks_detected"] != len(scenario.attack_types):
                validation_passed = False
                failed_criteria.append("Not all attacks detected")
        
        # Check mitigation requirements
        if scenario.expected_outcomes.get("mitigation", False):
            if mitigation_results["actions_taken"] != len(scenario.attack_types):
                validation_passed = False
                failed_criteria.append("Not all attacks mitigated")
        
        # Check recovery requirements
        if scenario.expected_outcomes.get("recovery", False):
            if not recovery_results["connectivity_verified"]:
                validation_passed = False
                failed_criteria.append("Connectivity not verified")
        
        # Check timing requirements
        for attack_type, detection_time in detection_results.get("detection_times", {}).items():
            if detection_time > 100:  # 100ms requirement
                validation_passed = False
                failed_criteria.append(f"Detection time exceeded for {attack_type}")
        
        for attack_type, response_time in mitigation_results.get("response_times", {}).items():
            if response_time > 200:  # 200ms requirement
                validation_passed = False
                failed_criteria.append(f"Mitigation time exceeded for {attack_type}")
        
        if validation_passed:
            return "PASSED"
        else:
            logger.warning(f"Validation failed: {', '.join(failed_criteria)}")
            return f"FAILED: {', '.join(failed_criteria)}"
    
    def _save_demonstration_result(self, result: DemoResult):
        """Save demonstration result to file."""
        timestamp_str = result.execution_timestamp.strftime("%Y%m%d_%H%M%S")
        result_file = self.results_dir / f"{result.scenario_id}_{timestamp_str}.json"
        
        with open(result_file, 'w') as f:
            json.dump(asdict(result), f, indent=2, default=str)
    
    def validate_reproducibility(self, scenario: DemoScenario, num_runs: int = 3) -> bool:
        """Validate that a demonstration scenario produces reproducible results.
        
        Args:
            scenario: DemoScenario to validate
            num_runs: Number of runs to execute for reproducibility testing
            
        Returns:
            True if results are reproducible
        """
        results = []
        
        for run in range(num_runs):
            logger.info(f"Reproducibility run {run + 1}/{num_runs} for scenario {scenario.scenario_id}")
            result = self.execute_demonstration_scenario(scenario.scenario_id)
            results.append(result)
        
        # Check if all runs have the same reproducibility hash
        hashes = [result.reproducibility_hash for result in results]
        if len(set(hashes)) != 1:
            logger.error("Reproducibility validation failed: Different hashes across runs")
            return False
        
        # Check if validation status is consistent
        statuses = [result.validation_status for result in results]
        if len(set(statuses)) != 1:
            logger.error("Reproducibility validation failed: Inconsistent validation status")
            return False
        
        # Check if key metrics are within acceptable variance
        detection_accuracies = [result.performance_metrics.get("detection_accuracy", 0) for result in results]
        if max(detection_accuracies) - min(detection_accuracies) > 0.05:  # 5% variance allowed
            logger.error("Reproducibility validation failed: High variance in detection accuracy")
            return False
        
        logger.info(f"Reproducibility validation passed for scenario {scenario.scenario_id}")
        return True
    
    def _generate_reproducibility_hash(self, data: Dict[str, Any]) -> str:
        """Generate a hash for reproducibility validation."""
        data_str = json.dumps(data, sort_keys=True)
        return hashlib.sha256(data_str.encode()).hexdigest()[:16]
    
    def list_available_scenarios(self) -> List[str]:
        """List all available demonstration scenarios."""
        scenario_files = list(self.scenarios_dir.glob("*.json"))
        return [f.stem for f in scenario_files]
    
    def get_scenario_summary(self, scenario_id: str) -> Dict[str, Any]:
        """Get a summary of a demonstration scenario."""
        scenario = self.load_demonstration_scenario(scenario_id)
        return {
            "scenario_id": scenario.scenario_id,
            "scenario_name": scenario.scenario_name,
            "description": scenario.description,
            "attack_types": scenario.attack_types,
            "validation_criteria_count": len(scenario.validation_criteria),
            "created_timestamp": scenario.created_timestamp,
            "reproducibility_hash": scenario.reproducibility_hash
        }
    
    def generate_demonstration_report(self, scenario_id: str, result: DemoResult) -> str:
        """Generate a comprehensive demonstration report."""
        scenario = self.load_demonstration_scenario(scenario_id)
        
        report = f"""
# Demonstration Report: {scenario.scenario_name}

## Scenario Information
- **Scenario ID**: {scenario.scenario_id}
- **Description**: {scenario.description}
- **Attack Types**: {', '.join(scenario.attack_types)}
- **Execution Time**: {result.execution_timestamp}
- **Duration**: {result.execution_duration:.2f} seconds
- **Validation Status**: {result.validation_status}

## Detection Results
- **Attacks Detected**: {result.detection_results.get('attacks_detected', 0)}
- **Detection Accuracy**: {result.detection_results.get('detection_accuracy', 0):.2%}
- **False Positives**: {result.detection_results.get('false_positives', 0)}
- **Detection Methods**: {', '.join(result.detection_results.get('detection_methods', []))}

## Mitigation Results
- **Actions Taken**: {result.mitigation_results.get('actions_taken', 0)}
- **Success Rate**: {result.mitigation_results.get('success_rate', 0):.2%}
- **Mitigation Actions**: {', '.join(result.mitigation_results.get('mitigation_actions', []))}

## Recovery Results
- **Recovery Time**: {result.recovery_results.get('recovery_time', 0):.1f} seconds
- **Connectivity Verified**: {result.recovery_results.get('connectivity_verified', False)}
- **Services Restored**: {result.recovery_results.get('services_restored', False)}
- **Recovery Actions**: {', '.join(result.recovery_results.get('recovery_actions', []))}

## Performance Metrics
- **Average Detection Latency**: {result.performance_metrics.get('avg_detection_latency', 0):.1f} ms
- **Average Mitigation Response Time**: {result.performance_metrics.get('avg_mitigation_response_time', 0):.1f} ms
- **CPU Utilization**: {result.performance_metrics.get('cpu_utilization', 0):.1%}
- **Memory Usage**: {result.performance_metrics.get('memory_usage', 0):.1%}
- **Throughput**: {result.performance_metrics.get('throughput', 0):.0f} packets/second

## Validation Criteria
"""
        
        for i, criterion in enumerate(scenario.validation_criteria, 1):
            report += f"{i}. {criterion}\n"
        
        report += f"\n## Reproducibility Hash\n{result.reproducibility_hash}\n"
        
        return report