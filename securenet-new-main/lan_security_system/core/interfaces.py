"""
Core interfaces and base classes for the LAN Security System components.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
import logging


class AttackType(Enum):
    """Enumeration of supported attack types."""
    ARP_SPOOFING = "arp_spoofing"
    MAC_FLOODING = "mac_flooding"
    DNS_SPOOFING = "dns_spoofing"


class DetectionMethod(Enum):
    """Detection method used to identify the attack."""
    SIGNATURE_BASED = "signature_based"
    ANOMALY_BASED = "anomaly_based"
    HYBRID = "hybrid"


@dataclass
class SecurityAlert:
    """Security alert data model."""
    timestamp: datetime
    alert_id: str
    attack_type: AttackType
    confidence_score: float
    source_mac: str
    source_ip: str
    target_mac: str
    target_ip: str
    affected_hosts: List[str]
    raw_packet_data: bytes
    detection_method: DetectionMethod


@dataclass
class NetworkBaseline:
    """Network baseline configuration model."""
    arp_table: Dict[str, str]  # IP -> MAC mappings
    dns_cache: Dict[str, str]  # Domain -> IP mappings
    mac_port_mappings: Dict[str, int]  # MAC -> Port mappings
    baseline_timestamp: datetime


@dataclass
class DetectionConfig:
    """Detection engine configuration parameters."""
    arp_rate_threshold: int = 10  # ARP requests per second
    mac_learning_threshold: int = 50  # MAC addresses per port
    cam_table_threshold: float = 0.9  # CAM table utilization
    dns_ttl_variance_threshold: int = 300  # TTL variance in seconds
    detection_window_size: int = 60  # Analysis window in seconds
    detection_latency_target: int = 100  # Maximum detection latency in milliseconds
    false_positive_threshold: float = 0.05  # Maximum acceptable false positive rate
    processing_threads: int = 4  # Number of packet processing worker threads
    queue_maxsize: int = 10000  # Max packet queue size to buffer bursts
    dns_safe_mode: bool = True  # DNS safe mode: alert-only, no hard mitigation until hardened
    # Optional exclusions/tuning
    excluded_source_ips: list = field(default_factory=list)  # IPs to ignore as sources
    trusted_dns_servers: list = field(default_factory=list)  # Known-good DNS servers to ignore as sources


@dataclass
class MitigationResult:
    """Result of a mitigation action."""
    success: bool
    mitigation_id: str
    actions_taken: List[str]
    timestamp: datetime
    error_message: Optional[str] = None


@dataclass
class RecoveryResult:
    """Result of a recovery operation."""
    success: bool
    recovery_id: str
    restored_components: List[str]
    timestamp: datetime
    verification_results: Dict[str, bool]
    error_message: Optional[str] = None


@dataclass
class LogEntry:
    """Log entry data model."""
    timestamp: datetime
    event_type: str
    source_component: str
    event_data: Dict[str, Any]
    integrity_hash: str
    log_level: str


class BaseDetector(ABC):
    """Base class for all detection components."""
    
    @abstractmethod
    def detect(self, packet_data: bytes) -> Optional[SecurityAlert]:
        """Analyze packet data and return security alert if threat detected."""
        pass
    
    @abstractmethod
    def update_baseline(self, baseline: NetworkBaseline) -> None:
        """Update detection baseline with new network state."""
        pass


class DetectionEngine(ABC):
    """Interface for the detection engine component."""
    
    @abstractmethod
    def start_monitoring(self, interface: str) -> None:
        """Start monitoring network traffic on specified interface."""
        pass
    
    @abstractmethod
    def register_detector(self, detector: BaseDetector) -> None:
        """Register a detector component."""
        pass
    
    @abstractmethod
    def set_alert_callback(self, callback: Callable[[SecurityAlert], None]) -> None:
        """Set callback function for alert notifications."""
        pass
    
    @abstractmethod
    def get_detection_stats(self) -> Dict[str, Any]:
        """Get detection engine statistics."""
        pass


class MitigationStrategy(ABC):
    """Base class for mitigation strategies."""
    
    @abstractmethod
    def execute(self, alert: SecurityAlert) -> MitigationResult:
        """Execute mitigation action for the given alert."""
        pass
    
    @abstractmethod
    def rollback(self, mitigation_id: str) -> bool:
        """Rollback a previously executed mitigation."""
        pass


class MitigationController(ABC):
    """Interface for the mitigation controller component."""
    
    @abstractmethod
    def register_mitigation_strategy(self, attack_type: AttackType, strategy: MitigationStrategy) -> None:
        """Register a mitigation strategy for specific attack type."""
        pass
    
    @abstractmethod
    def execute_mitigation(self, alert: SecurityAlert) -> MitigationResult:
        """Execute appropriate mitigation for the given alert."""
        pass
    
    @abstractmethod
    def rollback_mitigation(self, mitigation_id: str) -> bool:
        """Rollback a specific mitigation action."""
        pass


class RecoveryManager(ABC):
    """Interface for the recovery manager component."""
    
    @abstractmethod
    def save_network_baseline(self) -> None:
        """Save current network state as baseline."""
        pass
    
    @abstractmethod
    def initiate_recovery(self, attack_type: AttackType) -> RecoveryResult:
        """Initiate recovery process for specific attack type."""
        pass
    
    @abstractmethod
    def verify_network_health(self) -> Dict[str, bool]:
        """Verify network health and connectivity."""
        pass


class LoggingSystem(ABC):
    """Interface for the logging system component."""
    
    @abstractmethod
    def log_security_event(self, event: SecurityAlert) -> None:
        """Log a security event."""
        pass
    
    @abstractmethod
    def log_mitigation_action(self, action: MitigationResult) -> None:
        """Log a mitigation action."""
        pass
    
    @abstractmethod
    def log_recovery_confirmation(self, recovery: RecoveryResult) -> None:
        """Log recovery confirmation."""
        pass
    
    @abstractmethod
    def generate_console_alert(self, alert: SecurityAlert) -> None:
        """Generate real-time console alert."""
        pass
    
    @abstractmethod
    def ensure_log_integrity(self, log_entry: LogEntry) -> bool:
        """Ensure log entry integrity."""
        pass


class AttackSimulator(ABC):
    """Interface for the attack simulation module."""
    
    @abstractmethod
    def execute_arp_spoofing(self, target_ip: str, gateway_ip: str) -> None:
        """Execute ARP spoofing attack simulation."""
        pass
    
    @abstractmethod
    def execute_mac_flooding(self, interface: str, packet_count: int) -> None:
        """Execute MAC flooding attack simulation."""
        pass
    
    @abstractmethod
    def execute_dns_spoofing(self, target_domain: str, fake_ip: str) -> None:
        """Execute DNS spoofing attack simulation."""
        pass
    
    @abstractmethod
    def log_attack_initiation(self, attack_type: AttackType) -> None:
        """Log attack initiation."""
        pass
    
    @abstractmethod
    def get_supported_attacks(self) -> List[AttackType]:
        """Get list of supported attack types."""
        pass


class NetworkTestbed(ABC):
    """Interface for the network testbed component."""
    
    @abstractmethod
    def initialize_topology(self) -> None:
        """Initialize network topology."""
        pass
    
    @abstractmethod
    def verify_connectivity(self) -> bool:
        """Verify network connectivity."""
        pass
    
    @abstractmethod
    def enable_packet_capture(self, interface: str) -> None:
        """Enable packet capture on interface."""
        pass