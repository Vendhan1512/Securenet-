"""
Data models for the logging system.
"""

from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import hashlib
import json


class LogLevel(Enum):
    """Log level enumeration."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class EventType(Enum):
    """Event type enumeration."""
    SECURITY_EVENT = "security_event"
    MITIGATION_ACTION = "mitigation_action"
    RECOVERY_CONFIRMATION = "recovery_confirmation"
    SYSTEM_STATUS = "system_status"
    ALERT_GENERATED = "alert_generated"


@dataclass
class SecurityEventData:
    """Security event specific data."""
    attack_type: str
    source_mac: str
    source_ip: str
    target_mac: str
    target_ip: str
    affected_hosts: List[str]
    confidence_score: float
    detection_method: str
    alert_id: str


@dataclass
class MitigationActionData:
    """Mitigation action specific data."""
    mitigation_id: str
    attack_type: str
    actions_taken: List[str]
    success: bool
    error_message: Optional[str] = None


@dataclass
class RecoveryConfirmationData:
    """Recovery confirmation specific data."""
    recovery_id: str
    attack_type: str
    restored_components: List[str]
    verification_results: Dict[str, bool]
    success: bool
    error_message: Optional[str] = None


@dataclass
class AlertDestination:
    """Alert destination configuration."""
    destination_type: str  # console, email, webhook, etc.
    address: str
    enabled: bool = True
    retry_count: int = 3
    timeout: int = 30


@dataclass
class StructuredLogEntry:
    """Structured log entry with integrity protection."""
    timestamp: datetime
    event_type: EventType
    source_component: str
    log_level: LogLevel
    event_data: Dict[str, Any]
    integrity_hash: str
    
    @classmethod
    def create(cls, event_type: EventType, source_component: str, 
               log_level: LogLevel, event_data: Dict[str, Any]) -> 'StructuredLogEntry':
        """Create a new structured log entry with integrity hash."""
        timestamp = datetime.utcnow()
        
        # Create hash input from all fields except integrity_hash
        hash_input = {
            'timestamp': timestamp.isoformat(),
            'event_type': event_type.value,
            'source_component': source_component,
            'log_level': log_level.value,
            'event_data': event_data
        }
        
        # Generate integrity hash
        hash_string = json.dumps(hash_input, sort_keys=True, default=str)
        integrity_hash = hashlib.sha256(hash_string.encode()).hexdigest()
        
        return cls(
            timestamp=timestamp,
            event_type=event_type,
            source_component=source_component,
            log_level=log_level,
            event_data=event_data,
            integrity_hash=integrity_hash
        )
    
    def verify_integrity(self) -> bool:
        """Verify the integrity of this log entry."""
        # Recreate hash input
        hash_input = {
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type.value,
            'source_component': self.source_component,
            'log_level': self.log_level.value,
            'event_data': self.event_data
        }
        
        # Generate expected hash
        hash_string = json.dumps(hash_input, sort_keys=True, default=str)
        expected_hash = hashlib.sha256(hash_string.encode()).hexdigest()
        
        return self.integrity_hash == expected_hash
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert log entry to dictionary for serialization."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type.value,
            'source_component': self.source_component,
            'log_level': self.log_level.value,
            'event_data': self.event_data,
            'integrity_hash': self.integrity_hash
        }
    
    def to_json(self) -> str:
        """Convert log entry to JSON string."""
        return json.dumps(self.to_dict(), default=str)