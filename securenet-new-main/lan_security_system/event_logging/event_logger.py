"""
Structured event logging implementation.
"""

import json
import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
import logging

from ..core.interfaces import SecurityAlert, MitigationResult, RecoveryResult, LoggingSystem
from .models import (
    StructuredLogEntry, EventType, LogLevel, SecurityEventData, 
    MitigationActionData, RecoveryConfirmationData
)


class StructuredEventLogger:
    """Structured event logger with integrity protection and persistent storage."""
    
    def __init__(self, log_directory: str = "logs", max_file_size: int = 10 * 1024 * 1024):
        """
        Initialize the structured event logger.
        
        Args:
            log_directory: Directory to store log files
            max_file_size: Maximum size of log files before rotation (bytes)
        """
        self.log_directory = Path(log_directory)
        self.max_file_size = max_file_size
        self._lock = threading.Lock()
        
        # Create log directory if it doesn't exist
        self.log_directory.mkdir(parents=True, exist_ok=True)
        
        # Initialize log files
        self.security_log_file = self.log_directory / "security_events.jsonl"
        self.mitigation_log_file = self.log_directory / "mitigation_actions.jsonl"
        self.recovery_log_file = self.log_directory / "recovery_confirmations.jsonl"
        self.system_log_file = self.log_directory / "system_events.jsonl"
        
        # Setup standard logging for console/file output (non-intrusive)
        self._setup_console_logging()
    
    def _setup_console_logging(self) -> None:
        """Setup console/file logging without reconfiguring global/root handlers."""
        # Use the project logger hierarchy configured by setup_logging
        self.console_logger = logging.getLogger("lan_security_system")
        # Attach a dedicated file handler for local console log if not already present
        log_path = self.log_directory / "console.log"
        file_handler_exists = False
        for h in self.console_logger.handlers:
            try:
                if isinstance(h, logging.FileHandler) and getattr(h, 'baseFilename', None) == str(log_path):
                    file_handler_exists = True
                    break
            except Exception:
                continue
        if not file_handler_exists:
            fh = logging.FileHandler(log_path)
            fh.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
            self.console_logger.addHandler(fh)
    
    def _get_log_file_for_event_type(self, event_type: EventType) -> Path:
        """Get the appropriate log file for the event type."""
        if event_type == EventType.SECURITY_EVENT:
            return self.security_log_file
        elif event_type == EventType.MITIGATION_ACTION:
            return self.mitigation_log_file
        elif event_type == EventType.RECOVERY_CONFIRMATION:
            return self.recovery_log_file
        else:
            return self.system_log_file
    
    def _rotate_log_file_if_needed(self, log_file: Path) -> None:
        """Rotate log file if it exceeds maximum size."""
        if log_file.exists() and log_file.stat().st_size > self.max_file_size:
            # Create rotated filename with timestamp
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            rotated_name = f"{log_file.stem}_{timestamp}{log_file.suffix}"
            rotated_path = log_file.parent / rotated_name
            
            # Handle case where rotated file already exists (add counter)
            counter = 1
            while rotated_path.exists():
                rotated_name = f"{log_file.stem}_{timestamp}_{counter}{log_file.suffix}"
                rotated_path = log_file.parent / rotated_name
                counter += 1
            
            # Move current log to rotated file
            log_file.rename(rotated_path)
    
    def _write_log_entry(self, log_entry: StructuredLogEntry) -> None:
        """Write log entry to appropriate file with thread safety."""
        with self._lock:
            log_file = self._get_log_file_for_event_type(log_entry.event_type)
            
            # Rotate log file if needed
            self._rotate_log_file_if_needed(log_file)
            
            # Write log entry as JSON line
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry.to_json() + '\n')
    
    def log_security_event(self, alert: SecurityAlert) -> StructuredLogEntry:
        """
        Log a security event with complete attack information.
        
        Args:
            alert: Security alert containing attack details
            
        Returns:
            The created structured log entry
        """
        event_data = SecurityEventData(
            attack_type=alert.attack_type.value,
            source_mac=alert.source_mac,
            source_ip=alert.source_ip,
            target_mac=alert.target_mac,
            target_ip=alert.target_ip,
            affected_hosts=alert.affected_hosts,
            confidence_score=alert.confidence_score,
            detection_method=alert.detection_method.value,
            alert_id=alert.alert_id
        )
        
        log_entry = StructuredLogEntry.create(
            event_type=EventType.SECURITY_EVENT,
            source_component="detection_engine",
            log_level=LogLevel.WARNING,
            event_data=event_data.__dict__
        )
        
        self._write_log_entry(log_entry)
        return log_entry
    
    def log_mitigation_action(self, mitigation: MitigationResult) -> StructuredLogEntry:
        """
        Log a mitigation action with all containment measures.
        
        Args:
            mitigation: Mitigation result containing action details
            
        Returns:
            The created structured log entry
        """
        event_data = MitigationActionData(
            mitigation_id=mitigation.mitigation_id,
            attack_type="unknown",  # Will be enhanced when attack_type is added to MitigationResult
            actions_taken=mitigation.actions_taken,
            success=mitigation.success,
            error_message=mitigation.error_message
        )
        
        log_level = LogLevel.INFO if mitigation.success else LogLevel.ERROR
        
        log_entry = StructuredLogEntry.create(
            event_type=EventType.MITIGATION_ACTION,
            source_component="mitigation_controller",
            log_level=log_level,
            event_data=event_data.__dict__
        )
        
        self._write_log_entry(log_entry)
        return log_entry
    
    def log_recovery_confirmation(self, recovery: RecoveryResult) -> StructuredLogEntry:
        """
        Log recovery confirmation with verification results.
        
        Args:
            recovery: Recovery result containing restoration details
            
        Returns:
            The created structured log entry
        """
        event_data = RecoveryConfirmationData(
            recovery_id=recovery.recovery_id,
            attack_type="unknown",  # Will be enhanced when attack_type is added to RecoveryResult
            restored_components=recovery.restored_components,
            verification_results=recovery.verification_results,
            success=recovery.success,
            error_message=recovery.error_message
        )
        
        log_level = LogLevel.INFO if recovery.success else LogLevel.ERROR
        
        log_entry = StructuredLogEntry.create(
            event_type=EventType.RECOVERY_CONFIRMATION,
            source_component="recovery_manager",
            log_level=log_level,
            event_data=event_data.__dict__
        )
        
        self._write_log_entry(log_entry)
        return log_entry
    
    def verify_log_integrity(self, log_file: Optional[Path] = None) -> Dict[str, Any]:
        """
        Verify the integrity of log entries in a file.
        
        Args:
            log_file: Specific log file to verify, or None to verify all
            
        Returns:
            Dictionary with verification results
        """
        results = {
            'total_entries': 0,
            'valid_entries': 0,
            'invalid_entries': 0,
            'corrupted_files': []
        }
        
        log_files = [log_file] if log_file else [
            self.security_log_file,
            self.mitigation_log_file,
            self.recovery_log_file,
            self.system_log_file
        ]
        
        for file_path in log_files:
            if not file_path.exists():
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        if not line.strip():
                            continue
                            
                        try:
                            entry_dict = json.loads(line.strip())
                            results['total_entries'] += 1
                            
                            # Recreate log entry to verify integrity
                            log_entry = StructuredLogEntry(
                                timestamp=datetime.fromisoformat(entry_dict['timestamp']),
                                event_type=EventType(entry_dict['event_type']),
                                source_component=entry_dict['source_component'],
                                log_level=LogLevel(entry_dict['log_level']),
                                event_data=entry_dict['event_data'],
                                integrity_hash=entry_dict['integrity_hash']
                            )
                            
                            if log_entry.verify_integrity():
                                results['valid_entries'] += 1
                            else:
                                results['invalid_entries'] += 1
                                
                        except (json.JSONDecodeError, KeyError, ValueError) as e:
                            results['invalid_entries'] += 1
                            
            except Exception as e:
                results['corrupted_files'].append(str(file_path))
        
        return results
    
    def get_log_entries(self, event_type: Optional[EventType] = None, 
                       start_time: Optional[datetime] = None,
                       end_time: Optional[datetime] = None,
                       limit: Optional[int] = None) -> List[StructuredLogEntry]:
        """
        Retrieve log entries with optional filtering.
        
        Args:
            event_type: Filter by event type
            start_time: Filter entries after this time
            end_time: Filter entries before this time
            limit: Maximum number of entries to return
            
        Returns:
            List of matching log entries
        """
        entries = []
        
        log_files = []
        if event_type:
            log_files = [self._get_log_file_for_event_type(event_type)]
        else:
            log_files = [
                self.security_log_file,
                self.mitigation_log_file,
                self.recovery_log_file,
                self.system_log_file
            ]
        
        for file_path in log_files:
            if not file_path.exists():
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        if not line.strip():
                            continue
                            
                        try:
                            entry_dict = json.loads(line.strip())
                            entry_time = datetime.fromisoformat(entry_dict['timestamp'])
                            
                            # Apply time filters
                            if start_time and entry_time < start_time:
                                continue
                            if end_time and entry_time > end_time:
                                continue
                            
                            log_entry = StructuredLogEntry(
                                timestamp=entry_time,
                                event_type=EventType(entry_dict['event_type']),
                                source_component=entry_dict['source_component'],
                                log_level=LogLevel(entry_dict['log_level']),
                                event_data=entry_dict['event_data'],
                                integrity_hash=entry_dict['integrity_hash']
                            )
                            
                            entries.append(log_entry)
                            
                            # Apply limit
                            if limit and len(entries) >= limit:
                                return entries
                                
                        except (json.JSONDecodeError, KeyError, ValueError):
                            continue
                            
            except Exception:
                continue
        
        # Sort by timestamp (most recent first)
        entries.sort(key=lambda x: x.timestamp, reverse=True)
        
        if limit:
            entries = entries[:limit]
            
        return entries
    
    def ensure_logging_active(self) -> None:
        """Ensure logging system is active after recovery (self-healing mechanism)."""
        try:
            with self._lock:
                # Verify logger is not disabled
                if hasattr(self.console_logger, 'disabled'):
                    self.console_logger.disabled = False
                
                # Verify log files are writable
                for log_file in [self.security_log_file, self.mitigation_log_file, 
                                 self.recovery_log_file, self.system_log_file]:
                    # Create file if it doesn't exist
                    if not log_file.exists():
                        log_file.touch()
                
                # Verify handlers are attached to logger
                if not any(isinstance(h, logging.FileHandler) for h in self.console_logger.handlers):
                    self._setup_console_logging()
            
            self.console_logger.info("Event logging system re-enabled and ready for next events")
        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to ensure logging is active: {e}")