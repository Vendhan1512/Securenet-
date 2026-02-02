"""
Automated mitigation controller for the LAN Security System.
"""

import logging
import threading
import uuid
from datetime import datetime
from typing import Dict, Optional, Tuple

from ..core.interfaces import (
    AttackType, MitigationController, MitigationResult, MitigationStrategy, SecurityAlert
)
from ..core.infrastructure_detector import get_infrastructure_detector
from .strategies import (
    ARPSpoofingMitigationStrategy, DNSSpoofingMitigationStrategy, MACFloodingMitigationStrategy
)
from .cache_manager import CacheManager
from .traffic_filter import TrafficFilter


logger = logging.getLogger(__name__)


class AutomatedMitigationController(MitigationController):
    """Automated mitigation controller implementation."""
    
    def __init__(self, dns_safe_mode: bool = True):
        self.strategies: Dict[AttackType, MitigationStrategy] = {}
        self.active_mitigations: Dict[str, MitigationResult] = {}
        self.cache_manager = CacheManager()
        self.traffic_filter = TrafficFilter()
        self.dns_safe_mode = dns_safe_mode  # DNS safe mode: alert-only, never hard mitigate
        
        # Idempotent mitigation cache: (source_ip, attack_type) -> timestamp
        self.mitigation_cache: Dict[Tuple[str, str], datetime] = {}
        self.mitigation_cache_lock = threading.Lock()
        self.mitigation_ttl_seconds = 300  # 5 minutes default TTL
        
        # Register default mitigation strategies
        self._register_default_strategies()
    
    def _register_default_strategies(self) -> None:
        """Register default mitigation strategies for each attack type."""
        self.register_mitigation_strategy(
            AttackType.ARP_SPOOFING, 
            ARPSpoofingMitigationStrategy()
        )
        self.register_mitigation_strategy(
            AttackType.MAC_FLOODING, 
            MACFloodingMitigationStrategy()
        )
        self.register_mitigation_strategy(
            AttackType.DNS_SPOOFING, 
            DNSSpoofingMitigationStrategy()
        )
    
    def register_mitigation_strategy(self, attack_type: AttackType, strategy: MitigationStrategy) -> None:
        """Register a mitigation strategy for specific attack type."""
        self.strategies[attack_type] = strategy
        logger.info(f"Registered mitigation strategy for {attack_type.value}")
    
    def execute_mitigation(self, alert: SecurityAlert) -> MitigationResult:
        """Execute mitigation based on confidence thresholds with DNS safe mode and idempotency.
        
        Confidence-based decision engine:
        - < 0.80: IGNORE (likely false positive)
        - 0.80-0.85: ALERT_ONLY (suspicious but uncertain) - DNS only
        - 0.85-0.95: SOFT_MITIGATION → HARD_MITIGATION (ARP, MAC, etc)
        - >= 0.95: HARD_MITIGATION (aggressive blocking)
        
        DNS Safe Mode:
        - DNS_SPOOFING always ALERT_ONLY (never hard mitigation)
        - Even if confidence >= 0.95, DNS forced to alert-only
        
        Idempotent Mitigation:
        - Check if (source_ip, attack_type) already mitigated within TTL
        - Skip duplicate mitigation to prevent rule duplication
        """
        # Guard: Check for missing required fields
        missing_fields = []
        if not all([
            getattr(alert, 'source_ip', None),
            getattr(alert, 'source_mac', None),
            getattr(alert, 'target_ip', None),
            getattr(alert, 'target_mac', None)
        ]):
            if not getattr(alert, 'source_ip', None):
                missing_fields.append('source_ip')
            if not getattr(alert, 'source_mac', None):
                missing_fields.append('source_mac')
            if not getattr(alert, 'target_ip', None):
                missing_fields.append('target_ip')
            if not getattr(alert, 'target_mac', None):
                missing_fields.append('target_mac')
            error_msg = f"Mitigation aborted: missing required alert fields: {', '.join(missing_fields)}"
            logger.error(error_msg)
            return MitigationResult(
                success=False,
                mitigation_id=str(uuid.uuid4()),
                actions_taken=[],
                timestamp=datetime.now(),
                error_message=error_msg
            )
        
        logger.info(f"Executing mitigation for {alert.attack_type.value} from {alert.source_ip} (confidence: {alert.confidence_score:.2f})")
        
        # STEP 0.5: IDEMPOTENT CHECK - Skip if already mitigated within TTL
        cache_key = (alert.source_ip, alert.attack_type.value)
        if self._is_mitigation_within_ttl(cache_key):
            logger.info(f"Skipping duplicate mitigation for {cache_key[1]} from {cache_key[0]} (within TTL)")
            return MitigationResult(
                success=False,
                mitigation_id=str(uuid.uuid4()),
                actions_taken=[f"Skipped: already mitigated (within {self.mitigation_ttl_seconds}sec TTL)"],
                timestamp=datetime.now(),
                error_message="Duplicate mitigation skipped by idempotency cache"
            )
        
        # STEP 1: INFRASTRUCTURE SAFETY CHECK
        infra_detector = get_infrastructure_detector()
        is_infra, reason = infra_detector.is_infrastructure(alert.source_ip, alert.source_mac)
        if is_infra:
            logger.warning(f"ALERT-ONLY (infrastructure): {reason}")
            return MitigationResult(
                success=False,
                mitigation_id=str(uuid.uuid4()),
                actions_taken=[f"ALERT_ONLY: {reason}"],
                timestamp=datetime.now(),
                error_message=f"Source is critical infrastructure: {reason}"
            )
        
        # STEP 1.5: DNS SAFE MODE CHECK
        if alert.attack_type == AttackType.DNS_SPOOFING and self.dns_safe_mode:
            logger.warning(f"ALERT_ONLY (DNS safe mode enabled): {alert.attack_type.value} from {alert.source_ip}")
            return MitigationResult(
                success=False,
                mitigation_id=str(uuid.uuid4()),
                actions_taken=[f"ALERT_ONLY (DNS safe mode)"],
                timestamp=datetime.now(),
                error_message=f"DNS spoofing: safe mode prevents hard mitigation until fully hardened"
            )
        
        # STEP 2: CONFIDENCE-BASED DECISION
        if alert.confidence_score < 0.80:
            logger.info(f"IGNORE (confidence {alert.confidence_score:.2f}): {alert.attack_type.value} from {alert.source_ip}")
            return MitigationResult(
                success=False,
                mitigation_id=str(uuid.uuid4()),
                actions_taken=[],
                timestamp=datetime.now(),
                error_message=f"Confidence {alert.confidence_score:.2f} below 0.80 threshold"
            )
        
        elif alert.confidence_score < 0.85:
            logger.warning(f"ALERT_ONLY (confidence {alert.confidence_score:.2f}): {alert.attack_type.value} from {alert.source_ip}")
            return MitigationResult(
                success=False,
                mitigation_id=str(uuid.uuid4()),
                actions_taken=[f"ALERT_ONLY (confidence {alert.confidence_score:.2f})"],
                timestamp=datetime.now(),
                error_message=f"Insufficient confidence for hard mitigation"
            )
        
        # Confidence >= 0.85 for all attacks → Execute hard mitigation
        strategy = self.strategies.get(alert.attack_type)
        if not strategy:
            error_msg = f"No mitigation strategy registered for {alert.attack_type.value}"
            logger.error(error_msg)
            return MitigationResult(
                success=False,
                mitigation_id=str(uuid.uuid4()),
                actions_taken=[],
                timestamp=datetime.now(),
                error_message=error_msg
            )
        
        try:
            result = strategy.execute(alert)
            if result.success:
                # Record this mitigation in cache for idempotency
                self._record_mitigation(cache_key)
                
                self._perform_cache_cleanup(alert, result)
                self._perform_traffic_blocking(alert, result)
                self.active_mitigations[result.mitigation_id] = result
                logger.info(f"Successfully executed mitigation {result.mitigation_id}")
            else:
                logger.error(f"Mitigation execution failed: {result.error_message}")
            
            return result
        except Exception as e:
            error_msg = f"Exception during mitigation: {e}"
            logger.error(error_msg)
            return MitigationResult(
                success=False,
                mitigation_id=str(uuid.uuid4()),
                actions_taken=[],
                timestamp=datetime.now(),
                error_message=error_msg
            )
    
    def _perform_cache_cleanup(self, alert: SecurityAlert, result: MitigationResult) -> None:
        """Perform cache cleanup based on the attack type."""
        try:
            if alert.attack_type == AttackType.ARP_SPOOFING:
                # Mark ARP entries as poisoned and reset them
                self.cache_manager.mark_arp_entry_poisoned(alert.target_ip)
                if self.cache_manager.reset_arp_cache([alert.target_ip]):
                    result.actions_taken.append(f"Reset ARP cache for {alert.target_ip}")
                else:
                    logger.warning(f"Failed to reset ARP cache for {alert.target_ip}")
                    
            elif alert.attack_type == AttackType.DNS_SPOOFING:
                # Extract domain from the attack (simplified - in real implementation would parse DNS packet)
                # For now, we'll use a placeholder domain
                domain = "example.com"  # This would be extracted from the DNS packet
                self.cache_manager.mark_dns_entry_poisoned(domain)
                if self.cache_manager.flush_dns_cache([domain]):
                    result.actions_taken.append(f"Flushed DNS cache for {domain}")
                else:
                    logger.warning(f"Failed to flush DNS cache for {domain}")
                    
            elif alert.attack_type == AttackType.MAC_FLOODING:
                # For MAC flooding, perform general network state cleanup
                if self.cache_manager.cleanup_network_state(AttackType.MAC_FLOODING):
                    result.actions_taken.append("Performed MAC flooding cleanup")
                else:
                    logger.warning("Failed to perform MAC flooding cleanup")
                    
        except Exception as e:
            logger.error(f"Failed to perform cache cleanup: {e}")
    
    def _perform_traffic_blocking(self, alert: SecurityAlert, result: MitigationResult) -> None:
        """Perform traffic blocking to prevent further attacks from the source."""
        try:
            # Block the attack source
            success = self.traffic_filter.block_attack_source(alert, result.mitigation_id)
            
            if success:
                result.actions_taken.append(f"Blocked traffic from {alert.source_ip} ({alert.source_mac})")
                logger.info(f"Successfully blocked traffic from attack source {alert.source_ip}")
            else:
                logger.warning(f"Failed to block traffic from attack source {alert.source_ip}")
                
        except Exception as e:
            logger.error(f"Failed to perform traffic blocking: {e}")
    
    def rollback_mitigation(self, mitigation_id: str) -> bool:
        """Rollback a specific mitigation action."""
        logger.info(f"Rolling back mitigation {mitigation_id}")
        
        # Find the mitigation result
        mitigation_result = self.active_mitigations.get(mitigation_id)
        if not mitigation_result:
            logger.warning(f"No active mitigation found with ID {mitigation_id}")
            return False
        
        # Determine the attack type from the stored result
        # We need to find which strategy was used based on the actions taken
        strategy = self._get_strategy_for_mitigation(mitigation_result)
        if not strategy:
            logger.error(f"Could not determine strategy for mitigation {mitigation_id}")
            return False
        
        try:
            # Execute the rollback
            success = strategy.rollback(mitigation_id)
            
            if success:
                # Remove from active mitigations
                del self.active_mitigations[mitigation_id]
                logger.info(f"Successfully rolled back mitigation {mitigation_id}")
            else:
                logger.error(f"Failed to rollback mitigation {mitigation_id}")
            
            return success
            
        except Exception as e:
            logger.error(f"Exception during mitigation rollback: {e}")
            return False
    
    def _get_strategy_for_mitigation(self, mitigation_result: MitigationResult) -> Optional[MitigationStrategy]:
        """Determine which strategy was used for a mitigation based on actions taken."""
        actions = mitigation_result.actions_taken
        
        # Check for ARP spoofing mitigation patterns
        if any("Blocked MAC address" in action for action in actions):
            return self.strategies.get(AttackType.ARP_SPOOFING)
        
        # Check for MAC flooding mitigation patterns
        if any("Disabled switch port" in action for action in actions):
            return self.strategies.get(AttackType.MAC_FLOODING)
        
        # Check for DNS spoofing mitigation patterns
        if any("Blocked DNS server" in action for action in actions):
            return self.strategies.get(AttackType.DNS_SPOOFING)
        
        return None
    
    def get_active_mitigations(self) -> Dict[str, MitigationResult]:
        """Get all currently active mitigations."""
        return self.active_mitigations.copy()
    
    def get_mitigation_stats(self) -> Dict[str, int]:
        """Get mitigation statistics."""
        stats = {
            "total_mitigations": len(self.active_mitigations),
            "arp_spoofing_mitigations": 0,
            "mac_flooding_mitigations": 0,
            "dns_spoofing_mitigations": 0
        }
        
        for result in self.active_mitigations.values():
            actions = result.actions_taken
            if any("Blocked MAC address" in action for action in actions):
                stats["arp_spoofing_mitigations"] += 1
            elif any("Disabled switch port" in action for action in actions):
                stats["mac_flooding_mitigations"] += 1
            elif any("Blocked DNS server" in action for action in actions):
                stats["dns_spoofing_mitigations"] += 1
        
        return stats
    
    def get_cache_manager(self) -> CacheManager:
        """Get the cache manager instance."""
        return self.cache_manager
    
    def get_traffic_filter(self) -> TrafficFilter:
        """Get the traffic filter instance."""
        return self.traffic_filter
    
    def validate_mitigation_effectiveness(self, mitigation_id: str) -> bool:
        """Validate that a mitigation is effectively preventing attack traffic."""
        return self.traffic_filter.validate_mitigation_effectiveness(mitigation_id)
    
    def is_source_blocked(self, source_ip: str, source_mac: str = None) -> bool:
        """Check if a source is currently blocked."""
        return self.traffic_filter.is_source_blocked(source_ip, source_mac)
    
    def _is_mitigation_within_ttl(self, cache_key: Tuple[str, str]) -> bool:
        """Check if mitigation for (source_ip, attack_type) is already active and within TTL.
        
        Args:
            cache_key: (source_ip, attack_type_string) tuple
        
        Returns:
            True if mitigation is cached and within TTL, False otherwise
        """
        with self.mitigation_cache_lock:
            if cache_key not in self.mitigation_cache:
                return False
            
            time_since_mitigation = (datetime.now() - self.mitigation_cache[cache_key]).total_seconds()
            within_ttl = time_since_mitigation < self.mitigation_ttl_seconds
            
            if not within_ttl:
                # Expired - remove from cache
                del self.mitigation_cache[cache_key]
                logger.debug(f"Mitigation TTL expired for {cache_key[0]}/{cache_key[1]}, cleared from cache")
            
            return within_ttl
    
    def _record_mitigation(self, cache_key: Tuple[str, str]) -> None:
        """Record a mitigation in the idempotency cache with current timestamp.
        
        Args:
            cache_key: (source_ip, attack_type_string) tuple
        """
        with self.mitigation_cache_lock:
            self.mitigation_cache[cache_key] = datetime.now()
            logger.debug(f"Recorded mitigation in cache: {cache_key[0]}/{cache_key[1]} (TTL: {self.mitigation_ttl_seconds}sec)")
    
    def _cleanup_expired_mitigations(self) -> None:
        """Remove expired mitigation entries from cache (called periodically)."""
        with self.mitigation_cache_lock:
            current_time = datetime.now()
            expired_keys = []
            
            for cache_key, mitigation_time in self.mitigation_cache.items():
                time_since = (current_time - mitigation_time).total_seconds()
                if time_since >= self.mitigation_ttl_seconds:
                    expired_keys.append(cache_key)
            
            for key in expired_keys:
                del self.mitigation_cache[key]
                logger.debug(f"Cleaned up expired mitigation cache entry: {key[0]}/{key[1]}")
    
    def get_mitigation_cache_stats(self) -> Dict[str, int]:
        """Get statistics about the mitigation cache."""
        with self.mitigation_cache_lock:
            return {
                "cached_mitigations": len(self.mitigation_cache),
                "cache_ttl_seconds": self.mitigation_ttl_seconds
            }
    
    def reset_mitigation_state(self) -> None:
        """Reset mitigation state for self-healing after recovery (critical for next attack response)."""
        try:
            # Clear active mitigations for next cycle
            old_count = len(self.active_mitigations)
            self.active_mitigations.clear()
            
            # Clear mitigation cache for next cycle
            old_cache_count = len(self.mitigation_cache)
            self.mitigation_cache.clear()
            
            # Reset traffic filter state
            self.traffic_filter.blocked_sources.clear()
            self.traffic_filter.blocked_macs.clear()
            
            logger.info(f"Mitigation controller reset: cleared {old_count} active mitigations, {old_cache_count} cache entries, and blocked source tracking")
        except Exception as e:
            logger.error(f"Failed to reset mitigation state: {e}")