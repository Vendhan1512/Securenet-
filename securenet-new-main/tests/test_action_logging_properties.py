"""
Property-based tests for action logging functionality.

**Feature: lan-security-system, Property 23: Mitigation Action Documentation**
**Feature: lan-security-system, Property 24: Recovery Confirmation Logging**
**Validates: Requirements 6.2, 6.3**
"""

import tempfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from hypothesis import given, strategies as st, settings
import pytest

from lan_security_system.core.interfaces import MitigationResult, RecoveryResult, AttackType
from lan_security_system.logging.action_logger import ActionLogger
from lan_security_system.logging.models import EventType, LogLevel


# Test data generators - Using ASCII-safe characters to avoid Windows encoding issues
@st.composite
def mitigation_result_strategy(draw):
    """Generate random MitigationResult instances with ASCII-safe characters."""
    # Use ASCII printable characters excluding problematic ones for Windows console
    safe_alphabet = st.characters(min_codepoint=32, max_codepoint=126, 
                                 blacklist_characters='"\\`\r\n\t')
    
    return MitigationResult(
        success=draw(st.booleans()),
        mitigation_id=draw(st.text(min_size=1, max_size=30, alphabet=safe_alphabet)),
        actions_taken=draw(st.lists(
            st.text(min_size=1, max_size=50, alphabet=safe_alphabet),
            min_size=1, max_size=5
        )),
        timestamp=draw(st.datetimes(
            min_value=datetime(2020, 1, 1),
            max_value=datetime(2030, 12, 31)
        )),
        error_message=draw(st.one_of(
            st.none(),
            st.text(min_size=1, max_size=100, alphabet=safe_alphabet)
        ))
    )


@st.composite
def recovery_result_strategy(draw):
    """Generate random RecoveryResult instances with ASCII-safe characters."""
    # Use ASCII printable characters excluding problematic ones for Windows console
    safe_alphabet = st.characters(min_codepoint=32, max_codepoint=126, 
                                 blacklist_characters='"\\`\r\n\t')
    
    return RecoveryResult(
        success=draw(st.booleans()),
        recovery_id=draw(st.text(min_size=1, max_size=30, alphabet=safe_alphabet)),
        restored_components=draw(st.lists(
            st.text(min_size=1, max_size=30, alphabet=safe_alphabet),
            min_size=1, max_size=5
        )),
        timestamp=draw(st.datetimes(
            min_value=datetime(2020, 1, 1),
            max_value=datetime(2030, 12, 31)
        )),
        verification_results=draw(st.dictionaries(
            st.text(min_size=1, max_size=20, alphabet=safe_alphabet),
            st.booleans(),
            min_size=1, max_size=5
        )),
        error_message=draw(st.one_of(
            st.none(),
            st.text(min_size=1, max_size=100, alphabet=safe_alphabet)
        ))
    )


class TestActionLoggingProperties:
    """Property-based tests for action logging system."""
    
    def setup_method(self):
        """Setup test environment with fresh temporary directory."""
        # Create a unique temporary directory for each test
        self.temp_dir = tempfile.mkdtemp(prefix="action_logging_test_")
        self.logger = ActionLogger(log_directory=self.temp_dir)
    
    def teardown_method(self):
        """Cleanup test environment completely."""
        # Close any open file handles and cleanup logging handlers
        if hasattr(self.logger, 'action_logger'):
            for handler in self.logger.action_logger.handlers[:]:
                handler.close()
                self.logger.action_logger.removeHandler(handler)
        
        # Force cleanup of the logger instance
        self.logger = None
        
        # Clean up temporary directory with retry for Windows file locking
        import time
        for attempt in range(3):
            try:
                shutil.rmtree(self.temp_dir, ignore_errors=False)
                break
            except (OSError, PermissionError):
                if attempt < 2:
                    time.sleep(0.1)
                else:
                    shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @given(mitigation_result_strategy(), st.sampled_from(AttackType))
    @settings(max_examples=5, deadline=None)
    def test_property_23_mitigation_action_documentation(self, mitigation, attack_type):
        """
        Property 23: Mitigation Action Documentation
        For any executed mitigation action, the logger should document 
        all containment measures applied.
        **Validates: Requirements 6.2**
        """
        # Log the mitigation action
        log_entry = self.logger.log_mitigation_action(mitigation, attack_type)
        
        # Verify log entry structure
        assert log_entry.timestamp is not None
        assert log_entry.event_type == EventType.MITIGATION_ACTION
        assert log_entry.source_component == "mitigation_controller"
        
        # Verify all required mitigation documentation is present
        event_data = log_entry.event_data
        
        # Core mitigation information
        assert 'mitigation_id' in event_data
        assert 'attack_type' in event_data
        assert 'actions_taken' in event_data
        assert 'success' in event_data
        
        # Verify values match the original mitigation
        assert event_data['mitigation_id'] == mitigation.mitigation_id
        assert event_data['attack_type'] == attack_type.value
        assert event_data['actions_taken'] == mitigation.actions_taken
        assert event_data['success'] == mitigation.success
        
        # Verify audit trail information is documented
        assert 'execution_timestamp' in event_data
        assert 'containment_measures' in event_data
        assert 'affected_components' in event_data
        
        # Verify containment measures are properly categorized
        containment_measures = event_data['containment_measures']
        assert isinstance(containment_measures, dict)
        
        # All actions should be categorized somewhere
        all_categorized_actions = []
        for category_actions in containment_measures.values():
            all_categorized_actions.extend(category_actions)
        
        # Every action from the original mitigation should be categorized
        for action in mitigation.actions_taken:
            assert action in all_categorized_actions
        
        # Verify affected components are identified
        affected_components = event_data['affected_components']
        assert isinstance(affected_components, list)
        
        # Error message should be included if mitigation failed
        if not mitigation.success and mitigation.error_message:
            assert event_data.get('error_message') == mitigation.error_message
    
    @given(recovery_result_strategy(), st.sampled_from(AttackType))
    @settings(max_examples=5, deadline=None)
    def test_property_24_recovery_confirmation_logging(self, recovery, attack_type):
        """
        Property 24: Recovery Confirmation Logging
        For any completed network recovery, the logger should confirm 
        successful restoration with verification results.
        **Validates: Requirements 6.3**
        """
        # Log the recovery confirmation
        log_entry = self.logger.log_recovery_confirmation(recovery, attack_type)
        
        # Verify log entry structure
        assert log_entry.timestamp is not None
        assert log_entry.event_type == EventType.RECOVERY_CONFIRMATION
        assert log_entry.source_component == "recovery_manager"
        
        # Verify all required recovery documentation is present
        event_data = log_entry.event_data
        
        # Core recovery information
        assert 'recovery_id' in event_data
        assert 'attack_type' in event_data
        assert 'restored_components' in event_data
        assert 'verification_results' in event_data
        assert 'success' in event_data
        
        # Verify values match the original recovery
        assert event_data['recovery_id'] == recovery.recovery_id
        assert event_data['attack_type'] == attack_type.value
        assert event_data['restored_components'] == recovery.restored_components
        assert event_data['verification_results'] == recovery.verification_results
        assert event_data['success'] == recovery.success
        
        # Verify recovery-specific audit information is documented
        assert 'recovery_timestamp' in event_data
        assert 'verification_summary' in event_data
        assert 'restoration_steps' in event_data
        
        # Verify verification summary is properly calculated
        verification_summary = event_data['verification_summary']
        assert isinstance(verification_summary, dict)
        assert 'total_verification_checks' in verification_summary
        assert 'passed_checks' in verification_summary
        assert 'failed_checks' in verification_summary
        assert 'success_rate' in verification_summary
        assert 'failed_components' in verification_summary
        
        # Verify verification summary calculations are correct
        total_checks = len(recovery.verification_results)
        passed_checks = sum(1 for result in recovery.verification_results.values() if result)
        failed_checks = total_checks - passed_checks
        
        assert verification_summary['total_verification_checks'] == total_checks
        assert verification_summary['passed_checks'] == passed_checks
        assert verification_summary['failed_checks'] == failed_checks
        
        if total_checks > 0:
            expected_success_rate = passed_checks / total_checks
            assert abs(verification_summary['success_rate'] - expected_success_rate) < 0.001
        else:
            assert verification_summary['success_rate'] == 0.0
        
        # Verify failed components are correctly identified
        expected_failed_components = [
            component for component, result in recovery.verification_results.items() 
            if not result
        ]
        assert set(verification_summary['failed_components']) == set(expected_failed_components)
        
        # Verify restoration steps are properly categorized
        restoration_steps = event_data['restoration_steps']
        assert isinstance(restoration_steps, dict)
        
        # All restored components should be categorized somewhere
        all_categorized_components = []
        for category_components in restoration_steps.values():
            all_categorized_components.extend(category_components)
        
        # Every component from the original recovery should be categorized
        for component in recovery.restored_components:
            assert component in all_categorized_components
        
        # Error message should be included if recovery failed
        if not recovery.success and recovery.error_message:
            assert event_data.get('error_message') == recovery.error_message
    
    @given(st.lists(mitigation_result_strategy(), min_size=1, max_size=5))
    @settings(max_examples=3, deadline=None)
    def test_mitigation_audit_trail_retrieval(self, mitigations):
        """Test mitigation audit trail retrieval and filtering."""
        attack_type = AttackType.ARP_SPOOFING
        
        # Create a fresh logger for this specific test example
        example_temp_dir = tempfile.mkdtemp(prefix="mitigation_audit_test_")
        try:
            example_logger = ActionLogger(log_directory=example_temp_dir)
            
            # Log all mitigations
            for mitigation in mitigations:
                example_logger.log_mitigation_action(mitigation, attack_type)
            
            # Test retrieval without filters
            all_entries = example_logger.get_mitigation_audit_trail()
            assert len(all_entries) == len(mitigations)
            
            # Test retrieval with attack type filter
            filtered_entries = example_logger.get_mitigation_audit_trail(attack_type=attack_type)
            assert len(filtered_entries) == len(mitigations)
            
            # Test retrieval with specific mitigation ID
            if mitigations:
                specific_mitigation = mitigations[0]
                specific_entries = example_logger.get_mitigation_audit_trail(
                    mitigation_id=specific_mitigation.mitigation_id
                )
                assert len(specific_entries) >= 1
                assert all(entry.event_data['mitigation_id'] == specific_mitigation.mitigation_id 
                          for entry in specific_entries)
                          
            # Clean up the logger
            for handler in example_logger.action_logger.handlers[:]:
                handler.close()
                example_logger.action_logger.removeHandler(handler)
                
        finally:
            # Clean up the temporary directory
            shutil.rmtree(example_temp_dir, ignore_errors=True)
    
    @given(st.lists(recovery_result_strategy(), min_size=1, max_size=5))
    @settings(max_examples=3, deadline=None)
    def test_recovery_audit_trail_retrieval(self, recoveries):
        """Test recovery audit trail retrieval and filtering."""
        attack_type = AttackType.DNS_SPOOFING
        
        # Create a fresh logger for this specific test example
        example_temp_dir = tempfile.mkdtemp(prefix="recovery_audit_test_")
        try:
            example_logger = ActionLogger(log_directory=example_temp_dir)
            
            # Log all recoveries
            for recovery in recoveries:
                example_logger.log_recovery_confirmation(recovery, attack_type)
            
            # Test retrieval without filters
            all_entries = example_logger.get_recovery_audit_trail()
            assert len(all_entries) == len(recoveries)
            
            # Test retrieval with attack type filter
            filtered_entries = example_logger.get_recovery_audit_trail(attack_type=attack_type)
            assert len(filtered_entries) == len(recoveries)
            
            # Test retrieval with specific recovery ID
            if recoveries:
                specific_recovery = recoveries[0]
                specific_entries = example_logger.get_recovery_audit_trail(
                    recovery_id=specific_recovery.recovery_id
                )
                assert len(specific_entries) >= 1
                assert all(entry.event_data['recovery_id'] == specific_recovery.recovery_id 
                          for entry in specific_entries)
                          
            # Clean up the logger
            for handler in example_logger.action_logger.handlers[:]:
                handler.close()
                example_logger.action_logger.removeHandler(handler)
                
        finally:
            # Clean up the temporary directory
            shutil.rmtree(example_temp_dir, ignore_errors=True)
    
    @given(
        st.lists(mitigation_result_strategy(), min_size=1, max_size=3),
        st.lists(recovery_result_strategy(), min_size=1, max_size=3)
    )
    @settings(max_examples=3, deadline=None)
    def test_action_summary_report_generation(self, mitigations, recoveries):
        """Test comprehensive action summary report generation."""
        attack_type = AttackType.MAC_FLOODING
        
        # Create a fresh logger for this specific test example
        example_temp_dir = tempfile.mkdtemp(prefix="summary_report_test_")
        try:
            example_logger = ActionLogger(log_directory=example_temp_dir)
            
            # Log all actions
            for mitigation in mitigations:
                example_logger.log_mitigation_action(mitigation, attack_type)
            
            for recovery in recoveries:
                example_logger.log_recovery_confirmation(recovery, attack_type)
            
            # Generate summary report
            report = example_logger.generate_action_summary_report()
            
            # Verify report structure
            assert 'report_period' in report
            assert 'mitigation_statistics' in report
            assert 'recovery_statistics' in report
            assert 'overall_success_rate' in report
            
            # Verify mitigation statistics
            mitigation_stats = report['mitigation_statistics']
            assert mitigation_stats['total_mitigations'] == len(mitigations)
            
            expected_successful_mitigations = sum(1 for m in mitigations if m.success)
            expected_failed_mitigations = len(mitigations) - expected_successful_mitigations
            
            assert mitigation_stats['successful_mitigations'] == expected_successful_mitigations
            assert mitigation_stats['failed_mitigations'] == expected_failed_mitigations
            assert attack_type.value in mitigation_stats['attack_types_mitigated']
            
            # Verify recovery statistics
            recovery_stats = report['recovery_statistics']
            assert recovery_stats['total_recoveries'] == len(recoveries)
            
            expected_successful_recoveries = sum(1 for r in recoveries if r.success)
            expected_failed_recoveries = len(recoveries) - expected_successful_recoveries
            
            assert recovery_stats['successful_recoveries'] == expected_successful_recoveries
            assert recovery_stats['failed_recoveries'] == expected_failed_recoveries
            
            # Verify overall success rate calculation
            total_actions = len(mitigations) + len(recoveries)
            total_successful = expected_successful_mitigations + expected_successful_recoveries
            expected_overall_rate = total_successful / total_actions if total_actions > 0 else 0.0
            
            assert abs(report['overall_success_rate'] - expected_overall_rate) < 0.001
            
            # Clean up the logger
            for handler in example_logger.action_logger.handlers[:]:
                handler.close()
                example_logger.action_logger.removeHandler(handler)
                
        finally:
            # Clean up the temporary directory
            shutil.rmtree(example_temp_dir, ignore_errors=True)
    
    @given(st.integers(min_value=1, max_value=2))
    @settings(max_examples=5, deadline=None)
    def test_log_file_persistence_and_rotation(self, num_actions):
        """Test log file persistence and rotation for action logs."""
        # Create a separate logger with small file size limit to trigger rotation
        rotation_temp_dir = tempfile.mkdtemp(prefix="rotation_test_")
        try:
            small_logger = ActionLogger(
                log_directory=rotation_temp_dir,
                max_file_size=500  # Small limit to trigger rotation
            )
            
            # Generate large mitigation actions to exceed file size
            for i in range(num_actions):
                mitigation = MitigationResult(
                    success=True,
                    mitigation_id=f"test_mitigation_{i}",
                    actions_taken=[f"large_action_{j}" * 20 for j in range(10)],  # Large actions
                    timestamp=datetime.utcnow(),
                    error_message=None
                )
                small_logger.log_mitigation_action(mitigation, AttackType.ARP_SPOOFING)
            
            # Verify log files exist
            mitigation_files = list(Path(rotation_temp_dir).glob("mitigation_audit*.jsonl"))
            action_files = list(Path(rotation_temp_dir).glob("action_summary*.jsonl"))
            
            # Should have at least the main log files
            assert len(mitigation_files) >= 1
            assert len(action_files) >= 1
            
            # Verify audit trail retrieval still works after rotation
            entries = small_logger.get_mitigation_audit_trail()
            assert len(entries) == num_actions
            
            # Clean up the small logger
            for handler in small_logger.action_logger.handlers[:]:
                handler.close()
                small_logger.action_logger.removeHandler(handler)
                
        finally:
            # Clean up the temporary directory
            shutil.rmtree(rotation_temp_dir, ignore_errors=True)