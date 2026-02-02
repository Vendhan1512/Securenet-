"""
Mitigation and recovery action logging implementation.
"""

import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
import logging

from ..core.interfaces import MitigationResult, RecoveryResult, AttackType
from .models import (
    StructuredLogEntry, EventType, LogLevel, MitigationActionData, 
    RecoveryConfirmationData
)


class ActionLogger:
    """Logger for mitigation and recovery actions with audit trail capabilities."""
    
    def __init__(self, log_directory: str = "logs", max_file_size: int = 10 * 1024 * 1024):
        """
        Initialize the action logger.
        
        Args:
            log_directory: Directory to store log files
            max_file_size: Maximum size of log files before rotation (bytes)
        """
        self.log_directory = Path(log_directory)
        self.max_file_size = max_file_size
        self._lock = threading.Lock()
        
        # Create log directory if it doesn't exist
        self.log_directory.mkdir(parents=True, exist_ok=True)
        
        # Initialize specialized log files for actions
        self.mitigation_audit_file = self.log_directory / "mitigation_audit.jsonl"
        self.recovery_audit_file = self.log_directory / "recovery_audit.jsonl"
        self.action_summary_file = self.log_directory / "action_summary.jsonl"
        
        # Setup action-specific logging
        self._setup_action_logging()
    
    def _setup_action_logging(self) -> None:
        """Setup action-specific logging configuration."""
        self.action_logger = logging.getLogger("LAN_Security_Actions")
        self.action_logger.setLevel(logging.INFO)
        
        # Clear any existing handlers to avoid duplication
        for handler in self.action_logger.handlers[:]:
            self.action_logger.removeHandler(handler)
        
        # Create file handler for action logs with UTF-8 encoding
        action_handler = logging.FileHandler(
            self.log_directory / "actions.log", 
            encoding='utf-8'
        )
        action_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        action_handler.setFormatter(action_formatter)
        self.action_logger.addHandler(action_handler)
        
        # Prevent propagation to root logger to avoid console encoding issues
        self.action_logger.propagate = False
    
    def _rotate_log_file_if_needed(self, log_file: Path) -> None:
        """Rotate log file if it exceeds maximum size."""
        if log_file.exists() and log_file.stat().st_size > self.max_file_size:
            # Create rotated filename with timestamp
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            rotated_name = f"{log_file.stem}_{timestamp}{log_file.suffix}"
            rotated_path = log_file.parent / rotated_name
            
            # Move current log to rotated file
            try:
                log_file.rename(rotated_path)
            except FileExistsError:
                # If file exists, add a counter
                counter = 1
                while rotated_path.exists():
                    rotated_name = f"{log_file.stem}_{timestamp}_{counter}{log_file.suffix}"
                    rotated_path = log_file.parent / rotated_name
                    counter += 1
                log_file.rename(rotated_path)
    
    def _write_log_entry(self, log_entry: StructuredLogEntry, log_file: Path) -> None:
        """Write log entry to specified file with thread safety."""
        with self._lock:
            # Rotate log file if needed
            self._rotate_log_file_if_needed(log_file)
            
            # Write log entry as JSON line
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry.to_json() + '\n')
    
    def log_mitigation_action(self, mitigation: MitigationResult, 
                            attack_type: Optional[AttackType] = None,
                            additional_context: Optional[Dict[str, Any]] = None) -> StructuredLogEntry:
        """
        Log a mitigation action with complete containment documentation.
        
        Args:
            mitigation: Mitigation result containing action details
            attack_type: Type of attack being mitigated
            additional_context: Additional context information
            
        Returns:
            The created structured log entry
        """
        # Prepare comprehensive event data
        event_data = MitigationActionData(
            mitigation_id=mitigation.mitigation_id,
            attack_type=attack_type.value if attack_type else "unknown",
            actions_taken=mitigation.actions_taken,
            success=mitigation.success,
            error_message=mitigation.error_message
        ).__dict__
        
        # Add additional context if provided
        if additional_context:
            event_data.update(additional_context)
        
        # Add audit trail information
        event_data.update({
            'execution_timestamp': mitigation.timestamp.isoformat(),
            'containment_measures': self._extract_containment_measures(mitigation.actions_taken),
            'system_state_before': additional_context.get('system_state_before') if additional_context else None,
            'system_state_after': additional_context.get('system_state_after') if additional_context else None,
            'affected_components': self._identify_affected_components(mitigation.actions_taken)
        })
        
        log_level = LogLevel.INFO if mitigation.success else LogLevel.ERROR
        
        log_entry = StructuredLogEntry.create(
            event_type=EventType.MITIGATION_ACTION,
            source_component="mitigation_controller",
            log_level=log_level,
            event_data=event_data
        )
        
        # Write to both mitigation audit and general action logs
        self._write_log_entry(log_entry, self.mitigation_audit_file)
        self._write_log_entry(log_entry, self.action_summary_file)
        
        # Log to standard logger as well
        if mitigation.success:
            self.action_logger.info(
                f"Mitigation {mitigation.mitigation_id} executed successfully: {', '.join(mitigation.actions_taken)}"
            )
        else:
            self.action_logger.error(
                f"Mitigation {mitigation.mitigation_id} failed: {mitigation.error_message}"
            )
        
        return log_entry
    
    def log_recovery_confirmation(self, recovery: RecoveryResult,
                                attack_type: Optional[AttackType] = None,
                                additional_context: Optional[Dict[str, Any]] = None) -> StructuredLogEntry:
        """
        Log recovery confirmation with verification results and audit trail.
        
        Args:
            recovery: Recovery result containing restoration details
            attack_type: Type of attack being recovered from
            additional_context: Additional context information
            
        Returns:
            The created structured log entry
        """
        # Prepare comprehensive event data
        event_data = RecoveryConfirmationData(
            recovery_id=recovery.recovery_id,
            attack_type=attack_type.value if attack_type else "unknown",
            restored_components=recovery.restored_components,
            verification_results=recovery.verification_results,
            success=recovery.success,
            error_message=recovery.error_message
        ).__dict__
        
        # Add additional context if provided
        if additional_context:
            event_data.update(additional_context)
        
        # Add recovery-specific audit information
        event_data.update({
            'recovery_timestamp': recovery.timestamp.isoformat(),
            'verification_summary': self._create_verification_summary(recovery.verification_results),
            'restoration_steps': self._extract_restoration_steps(recovery.restored_components),
            'network_health_status': additional_context.get('network_health_status') if additional_context else None,
            'baseline_comparison': additional_context.get('baseline_comparison') if additional_context else None
        })
        
        log_level = LogLevel.INFO if recovery.success else LogLevel.ERROR
        
        log_entry = StructuredLogEntry.create(
            event_type=EventType.RECOVERY_CONFIRMATION,
            source_component="recovery_manager",
            log_level=log_level,
            event_data=event_data
        )
        
        # Write to both recovery audit and general action logs
        self._write_log_entry(log_entry, self.recovery_audit_file)
        self._write_log_entry(log_entry, self.action_summary_file)
        
        # Log to standard logger as well
        if recovery.success:
            self.action_logger.info(
                f"Recovery {recovery.recovery_id} completed successfully: {', '.join(recovery.restored_components)}"
            )
        else:
            self.action_logger.error(
                f"Recovery {recovery.recovery_id} failed: {recovery.error_message}"
            )
        
        return log_entry
    
    def _extract_containment_measures(self, actions_taken: List[str]) -> Dict[str, List[str]]:
        """Extract and categorize containment measures from actions taken."""
        containment_measures = {
            'network_isolation': [],
            'access_control': [],
            'traffic_filtering': [],
            'cache_management': [],
            'port_control': [],
            'other': []
        }
        
        for action in actions_taken:
            action_lower = action.lower()
            if any(keyword in action_lower for keyword in ['block', 'isolate', 'disconnect']):
                containment_measures['network_isolation'].append(action)
            elif any(keyword in action_lower for keyword in ['firewall', 'rule', 'filter']):
                containment_measures['traffic_filtering'].append(action)
            elif any(keyword in action_lower for keyword in ['cache', 'flush', 'reset']):
                containment_measures['cache_management'].append(action)
            elif any(keyword in action_lower for keyword in ['port', 'disable', 'shutdown']):
                containment_measures['port_control'].append(action)
            elif any(keyword in action_lower for keyword in ['access', 'permission', 'deny']):
                containment_measures['access_control'].append(action)
            else:
                containment_measures['other'].append(action)
        
        # Remove empty categories
        return {k: v for k, v in containment_measures.items() if v}
    
    def _identify_affected_components(self, actions_taken: List[str]) -> List[str]:
        """Identify system components affected by mitigation actions."""
        components = set()
        
        for action in actions_taken:
            action_lower = action.lower()
            if any(keyword in action_lower for keyword in ['firewall', 'iptables', 'nftables']):
                components.add('firewall')
            elif any(keyword in action_lower for keyword in ['switch', 'port']):
                components.add('network_switch')
            elif any(keyword in action_lower for keyword in ['arp', 'cache']):
                components.add('arp_cache')
            elif any(keyword in action_lower for keyword in ['dns']):
                components.add('dns_cache')
            elif any(keyword in action_lower for keyword in ['route', 'routing']):
                components.add('routing_table')
        
        return list(components)
    
    def _create_verification_summary(self, verification_results: Dict[str, bool]) -> Dict[str, Any]:
        """Create a summary of verification results."""
        total_checks = len(verification_results)
        passed_checks = sum(1 for result in verification_results.values() if result)
        failed_checks = total_checks - passed_checks
        
        return {
            'total_verification_checks': total_checks,
            'passed_checks': passed_checks,
            'failed_checks': failed_checks,
            'success_rate': passed_checks / total_checks if total_checks > 0 else 0.0,
            'failed_components': [component for component, result in verification_results.items() if not result]
        }
    
    def _extract_restoration_steps(self, restored_components: List[str]) -> Dict[str, List[str]]:
        """Extract and categorize restoration steps from restored components."""
        restoration_steps = {
            'cache_restoration': [],
            'connectivity_restoration': [],
            'service_restoration': [],
            'configuration_restoration': [],
            'other': []
        }
        
        for component in restored_components:
            component_lower = component.lower()
            if any(keyword in component_lower for keyword in ['cache', 'arp', 'dns']):
                restoration_steps['cache_restoration'].append(component)
            elif any(keyword in component_lower for keyword in ['connectivity', 'network', 'gateway']):
                restoration_steps['connectivity_restoration'].append(component)
            elif any(keyword in component_lower for keyword in ['service', 'daemon', 'process']):
                restoration_steps['service_restoration'].append(component)
            elif any(keyword in component_lower for keyword in ['config', 'setting', 'parameter']):
                restoration_steps['configuration_restoration'].append(component)
            else:
                restoration_steps['other'].append(component)
        
        # Remove empty categories
        return {k: v for k, v in restoration_steps.items() if v}
    
    def get_mitigation_audit_trail(self, mitigation_id: Optional[str] = None,
                                 attack_type: Optional[AttackType] = None,
                                 start_time: Optional[datetime] = None,
                                 end_time: Optional[datetime] = None) -> List[StructuredLogEntry]:
        """
        Retrieve mitigation audit trail with optional filtering.
        
        Args:
            mitigation_id: Filter by specific mitigation ID
            attack_type: Filter by attack type
            start_time: Filter entries after this time
            end_time: Filter entries before this time
            
        Returns:
            List of matching mitigation log entries
        """
        entries = []
        
        # Get all mitigation audit files (including rotated ones)
        mitigation_files = list(self.log_directory.glob("mitigation_audit*.jsonl"))
        
        for log_file in mitigation_files:
            if not log_file.exists():
                continue
                
            try:
                with open(log_file, 'r', encoding='utf-8') as f:
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
                            
                            # Apply mitigation ID filter
                            if mitigation_id and entry_dict['event_data'].get('mitigation_id') != mitigation_id:
                                continue
                            
                            # Apply attack type filter
                            if attack_type and entry_dict['event_data'].get('attack_type') != attack_type.value:
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
                            
                        except (json.JSONDecodeError, KeyError, ValueError):
                            continue
            
            except Exception:
                continue
        
        # Sort by timestamp (most recent first)
        entries.sort(key=lambda x: x.timestamp, reverse=True)
        return entries
    
    def get_recovery_audit_trail(self, recovery_id: Optional[str] = None,
                               attack_type: Optional[AttackType] = None,
                               start_time: Optional[datetime] = None,
                               end_time: Optional[datetime] = None) -> List[StructuredLogEntry]:
        """
        Retrieve recovery audit trail with optional filtering.
        
        Args:
            recovery_id: Filter by specific recovery ID
            attack_type: Filter by attack type
            start_time: Filter entries after this time
            end_time: Filter entries before this time
            
        Returns:
            List of matching recovery log entries
        """
        entries = []
        
        # Get all recovery audit files (including rotated ones)
        recovery_files = list(self.log_directory.glob("recovery_audit*.jsonl"))
        
        for log_file in recovery_files:
            if not log_file.exists():
                continue
                
            try:
                with open(log_file, 'r', encoding='utf-8') as f:
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
                            
                            # Apply recovery ID filter
                            if recovery_id and entry_dict['event_data'].get('recovery_id') != recovery_id:
                                continue
                            
                            # Apply attack type filter
                            if attack_type and entry_dict['event_data'].get('attack_type') != attack_type.value:
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
                            
                        except (json.JSONDecodeError, KeyError, ValueError):
                            continue
            
            except Exception:
                continue
        
        # Sort by timestamp (most recent first)
        entries.sort(key=lambda x: x.timestamp, reverse=True)
        return entries
    
    def generate_action_summary_report(self, start_time: Optional[datetime] = None,
                                     end_time: Optional[datetime] = None) -> Dict[str, Any]:
        """
        Generate a comprehensive summary report of all actions taken.
        
        Args:
            start_time: Report start time
            end_time: Report end time
            
        Returns:
            Dictionary containing action summary statistics
        """
        mitigation_entries = self.get_mitigation_audit_trail(start_time=start_time, end_time=end_time)
        recovery_entries = self.get_recovery_audit_trail(start_time=start_time, end_time=end_time)
        
        # Calculate mitigation statistics
        mitigation_stats = {
            'total_mitigations': len(mitigation_entries),
            'successful_mitigations': sum(1 for entry in mitigation_entries 
                                        if entry.event_data.get('success', False)),
            'failed_mitigations': sum(1 for entry in mitigation_entries 
                                    if not entry.event_data.get('success', True)),
            'attack_types_mitigated': list(set(entry.event_data.get('attack_type', 'unknown') 
                                             for entry in mitigation_entries)),
            'most_common_actions': self._get_most_common_actions(mitigation_entries)
        }
        
        # Calculate recovery statistics
        recovery_stats = {
            'total_recoveries': len(recovery_entries),
            'successful_recoveries': sum(1 for entry in recovery_entries 
                                       if entry.event_data.get('success', False)),
            'failed_recoveries': sum(1 for entry in recovery_entries 
                                   if not entry.event_data.get('success', True)),
            'components_restored': self._get_restored_components_summary(recovery_entries),
            'average_verification_success_rate': self._calculate_average_verification_rate(recovery_entries)
        }
        
        return {
            'report_period': {
                'start_time': start_time.isoformat() if start_time else None,
                'end_time': end_time.isoformat() if end_time else None
            },
            'mitigation_statistics': mitigation_stats,
            'recovery_statistics': recovery_stats,
            'overall_success_rate': self._calculate_overall_success_rate(mitigation_entries, recovery_entries)
        }
    
    def _get_most_common_actions(self, entries: List[StructuredLogEntry]) -> Dict[str, int]:
        """Get the most common mitigation actions."""
        action_counts = {}
        for entry in entries:
            actions = entry.event_data.get('actions_taken', [])
            for action in actions:
                action_counts[action] = action_counts.get(action, 0) + 1
        
        # Return top 10 most common actions
        return dict(sorted(action_counts.items(), key=lambda x: x[1], reverse=True)[:10])
    
    def _get_restored_components_summary(self, entries: List[StructuredLogEntry]) -> Dict[str, int]:
        """Get summary of restored components."""
        component_counts = {}
        for entry in entries:
            components = entry.event_data.get('restored_components', [])
            for component in components:
                component_counts[component] = component_counts.get(component, 0) + 1
        
        return component_counts
    
    def _calculate_average_verification_rate(self, entries: List[StructuredLogEntry]) -> float:
        """Calculate average verification success rate."""
        if not entries:
            return 0.0
        
        total_rate = 0.0
        count = 0
        
        for entry in entries:
            verification_summary = entry.event_data.get('verification_summary', {})
            success_rate = verification_summary.get('success_rate', 0.0)
            total_rate += success_rate
            count += 1
        
        return total_rate / count if count > 0 else 0.0
    
    def _calculate_overall_success_rate(self, mitigation_entries: List[StructuredLogEntry],
                                      recovery_entries: List[StructuredLogEntry]) -> float:
        """Calculate overall success rate for all actions."""
        total_actions = len(mitigation_entries) + len(recovery_entries)
        if total_actions == 0:
            return 0.0
        
        successful_actions = (
            sum(1 for entry in mitigation_entries if entry.event_data.get('success', False)) +
            sum(1 for entry in recovery_entries if entry.event_data.get('success', False))
        )
        
        return successful_actions / total_actions