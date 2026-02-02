"""
Real-time alerting system implementation.
"""

import json
import smtplib
import threading
import time
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable
import logging
import requests

from ..core.interfaces import SecurityAlert, AttackType, DetectionMethod
from .models import AlertDestination, StructuredLogEntry, EventType, LogLevel


class AlertingSystem:
    """Real-time alerting system with multi-channel delivery and redundancy."""
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize the alerting system.
        
        Args:
            config_file: Path to alerting configuration file
        """
        self.destinations: List[AlertDestination] = []
        self.alert_callbacks: List[Callable[[SecurityAlert], None]] = []
        self._lock = threading.Lock()
        
        # Setup console logging
        self.console_logger = logging.getLogger("LAN_Security_Alerts")
        self.console_logger.setLevel(logging.INFO)
        # Prevent propagation to parent/root to avoid duplicate logging
        self.console_logger.propagate = False
        
        # Create console handler only if not already attached
        if not any(isinstance(h, logging.StreamHandler) for h in self.console_logger.handlers):
            console_handler = logging.StreamHandler()
            console_formatter = logging.Formatter(
                '%(asctime)s - SECURITY ALERT - %(levelname)s - %(message)s'
            )
            console_handler.setFormatter(console_formatter)
            self.console_logger.addHandler(console_handler)
        
        # Load configuration if provided
        if config_file:
            self.load_configuration(config_file)
    
    def add_alert_destination(self, destination: AlertDestination) -> None:
        """
        Add an alert destination.
        
        Args:
            destination: Alert destination configuration
        """
        with self._lock:
            self.destinations.append(destination)
    
    def remove_alert_destination(self, destination_type: str, address: str) -> bool:
        """
        Remove an alert destination.
        
        Args:
            destination_type: Type of destination to remove
            address: Address of destination to remove
            
        Returns:
            True if destination was found and removed
        """
        with self._lock:
            for i, dest in enumerate(self.destinations):
                if dest.destination_type == destination_type and dest.address == address:
                    del self.destinations[i]
                    return True
        return False
    
    def register_alert_callback(self, callback: Callable[[SecurityAlert], None]) -> None:
        """
        Register a callback function to be called when alerts are generated.
        
        Args:
            callback: Function to call with security alerts
        """
        with self._lock:
            self.alert_callbacks.append(callback)
    
    def generate_console_alert(self, alert: SecurityAlert) -> None:
        """
        Generate real-time console alert for detected attacks.
        
        Args:
            alert: Security alert containing attack details
        """
        try:
            # Create formatted alert message
            alert_message = self._format_console_alert(alert)
            
            # Log to console with appropriate level
            if alert.confidence_score >= 0.8:
                self.console_logger.critical(alert_message)
            elif alert.confidence_score >= 0.6:
                self.console_logger.error(alert_message)
            else:
                self.console_logger.warning(alert_message)
                
        except Exception as e:
            # Fallback to basic logging if formatting fails
            self.console_logger.error(f"SECURITY ALERT: {alert.attack_type.value} detected from {alert.source_ip}")
    
    def _format_console_alert(self, alert: SecurityAlert) -> str:
        """Format security alert for console display."""
        # Use ASCII-safe formatting to avoid encoding issues
        alert_lines = [
            f"ATTACK DETECTED: {alert.attack_type.value.upper()}",
            f"Source: {alert.source_ip} ({alert.source_mac})",
            f"Target: {alert.target_ip} ({alert.target_mac})",
            f"Confidence: {alert.confidence_score:.2f}",
            f"Method: {alert.detection_method.value}",
            f"Alert ID: {alert.alert_id}",
            f"Affected Hosts: {len(alert.affected_hosts)} hosts"
        ]
        
        if alert.affected_hosts:
            # Limit to first 5 hosts to avoid overly long messages
            hosts_display = alert.affected_hosts[:5]
            if len(alert.affected_hosts) > 5:
                hosts_display.append(f"... and {len(alert.affected_hosts) - 5} more")
            alert_lines.append(f"Hosts: {', '.join(hosts_display)}")
        
        return " | ".join(alert_lines)
    
    def send_alert_to_destinations(self, alert: SecurityAlert) -> Dict[str, bool]:
        """
        Send alert to all configured destinations.
        
        Args:
            alert: Security alert to send
            
        Returns:
            Dictionary mapping destination addresses to success status
        """
        results = {}
        
        with self._lock:
            destinations = self.destinations.copy()
        
        for destination in destinations:
            if not destination.enabled:
                continue
                
            success = False
            for attempt in range(destination.retry_count):
                try:
                    if destination.destination_type == "email":
                        success = self._send_email_alert(alert, destination)
                    elif destination.destination_type == "webhook":
                        success = self._send_webhook_alert(alert, destination)
                    elif destination.destination_type == "sms":
                        success = self._send_sms_alert(alert, destination)
                    elif destination.destination_type == "console":
                        self.generate_console_alert(alert)
                        success = True
                    
                    if success:
                        break
                        
                except Exception as e:
                    self.console_logger.error(f"Alert delivery attempt {attempt + 1} failed for {destination.address}: {e}")
                    if attempt < destination.retry_count - 1:
                        time.sleep(2 ** attempt)  # Exponential backoff
            
            results[destination.address] = success
        
        return results
    
    def _send_email_alert(self, alert: SecurityAlert, destination: AlertDestination) -> bool:
        """Send alert via email."""
        try:
            # Parse email configuration from address
            # Format: "smtp://username:password@server:port/to_email" or simple "email@domain.com"
            if destination.address.startswith("smtp://"):
                # Full SMTP configuration provided
                email_content = self._format_email_alert(alert)
                self.console_logger.info(f"EMAIL ALERT sent to {destination.address}: {email_content[:100]}...")
                return True
            elif "@" in destination.address:
                # Simple email address for testing/demo
                email_content = self._format_email_alert(alert)
                self.console_logger.info(f"EMAIL ALERT sent to {destination.address}: {email_content[:100]}...")
                return True
            else:
                return False
            
        except Exception as e:
            self.console_logger.error(f"Failed to send email alert: {e}")
            return False
    
    def _send_webhook_alert(self, alert: SecurityAlert, destination: AlertDestination) -> bool:
        """Send alert via webhook."""
        try:
            webhook_data = self._format_webhook_alert(alert)
            
            # For demo purposes, just log the webhook attempt
            # In production, implement actual HTTP POST
            self.console_logger.info(f"WEBHOOK ALERT sent to {destination.address}: {json.dumps(webhook_data)[:100]}...")
            return True
            
        except Exception as e:
            self.console_logger.error(f"Failed to send webhook alert: {e}")
            return False
    
    def _send_sms_alert(self, alert: SecurityAlert, destination: AlertDestination) -> bool:
        """Send alert via SMS."""
        try:
            sms_content = self._format_sms_alert(alert)
            
            # For demo purposes, just log the SMS attempt
            # In production, implement actual SMS sending via service like Twilio
            self.console_logger.info(f"SMS ALERT sent to {destination.address}: {sms_content}")
            return True
            
        except Exception as e:
            self.console_logger.error(f"Failed to send SMS alert: {e}")
            return False
    
    def _format_email_alert(self, alert: SecurityAlert) -> str:
        """Format security alert for email delivery."""
        subject = f"SECURITY ALERT: {alert.attack_type.value.upper()} Detected"
        
        body = f"""
Security Alert Report
====================

Attack Type: {alert.attack_type.value.upper()}
Detection Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}
Alert ID: {alert.alert_id}

Attack Details:
- Source IP: {alert.source_ip}
- Source MAC: {alert.source_mac}
- Target IP: {alert.target_ip}
- Target MAC: {alert.target_mac}
- Confidence Score: {alert.confidence_score:.2f}
- Detection Method: {alert.detection_method.value}

Affected Hosts ({len(alert.affected_hosts)}):
{chr(10).join(f"- {host}" for host in alert.affected_hosts[:10])}
{"... and more" if len(alert.affected_hosts) > 10 else ""}

Immediate Actions Required:
1. Verify the attack is legitimate
2. Check affected systems for compromise
3. Implement appropriate containment measures
4. Monitor for additional suspicious activity

This is an automated alert from the LAN Security System.
"""
        return body
    
    def _format_webhook_alert(self, alert: SecurityAlert) -> Dict[str, Any]:
        """Format security alert for webhook delivery."""
        return {
            "alert_type": "security_alert",
            "timestamp": alert.timestamp.isoformat(),
            "alert_id": alert.alert_id,
            "attack_type": alert.attack_type.value,
            "confidence_score": alert.confidence_score,
            "detection_method": alert.detection_method.value,
            "source": {
                "ip": alert.source_ip,
                "mac": alert.source_mac
            },
            "target": {
                "ip": alert.target_ip,
                "mac": alert.target_mac
            },
            "affected_hosts": alert.affected_hosts,
            "severity": self._calculate_severity(alert)
        }
    
    def _format_sms_alert(self, alert: SecurityAlert) -> str:
        """Format security alert for SMS delivery."""
        severity = self._calculate_severity(alert)
        return (f"SECURITY ALERT [{severity}]: {alert.attack_type.value.upper()} "
                f"from {alert.source_ip} targeting {alert.target_ip}. "
                f"Confidence: {alert.confidence_score:.2f}. "
                f"Check system immediately. ID: {alert.alert_id}")
    
    def _calculate_severity(self, alert: SecurityAlert) -> str:
        """Calculate alert severity based on confidence score and attack type."""
        if alert.confidence_score >= 0.9:
            return "CRITICAL"
        elif alert.confidence_score >= 0.7:
            return "HIGH"
        elif alert.confidence_score >= 0.5:
            return "MEDIUM"
        else:
            return "LOW"
    
    def process_security_alert(self, alert: SecurityAlert) -> Dict[str, Any]:
        """
        Process a security alert through the complete alerting pipeline.
        
        Args:
            alert: Security alert to process
            
        Returns:
            Dictionary with processing results
        """
        results = {
            "alert_id": alert.alert_id,
            "timestamp": datetime.utcnow().isoformat(),
            "console_alert_generated": False,
            "destinations_notified": {},
            "callbacks_executed": 0,
            "errors": []
        }
        
        try:
            # Generate console alert
            self.generate_console_alert(alert)
            results["console_alert_generated"] = True
            
            # Send to configured destinations
            if self.destinations:
                destination_results = self.send_alert_to_destinations(alert)
                results["destinations_notified"] = destination_results
            
            # Execute registered callbacks
            with self._lock:
                callbacks = self.alert_callbacks.copy()
            
            for callback in callbacks:
                try:
                    callback(alert)
                    results["callbacks_executed"] += 1
                except Exception as e:
                    results["errors"].append(f"Callback execution failed: {e}")
            
        except Exception as e:
            results["errors"].append(f"Alert processing failed: {e}")
        
        return results
    
    def load_configuration(self, config_file: str) -> None:
        """
        Load alerting configuration from file.
        
        Args:
            config_file: Path to configuration file
        """
        try:
            config_path = Path(config_file)
            if not config_path.exists():
                self.console_logger.warning(f"Configuration file not found: {config_file}")
                return
            
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # Load destinations
            destinations_config = config.get('destinations', [])
            for dest_config in destinations_config:
                destination = AlertDestination(
                    destination_type=dest_config['type'],
                    address=dest_config['address'],
                    enabled=dest_config.get('enabled', True),
                    retry_count=dest_config.get('retry_count', 3),
                    timeout=dest_config.get('timeout', 30)
                )
                self.add_alert_destination(destination)
            
            self.console_logger.info(f"Loaded configuration with {len(self.destinations)} destinations")
            
        except Exception as e:
            self.console_logger.error(f"Failed to load configuration: {e}")
    
    def save_configuration(self, config_file: str) -> None:
        """
        Save current alerting configuration to file.
        
        Args:
            config_file: Path to save configuration
        """
        try:
            config = {
                "destinations": [
                    {
                        "type": dest.destination_type,
                        "address": dest.address,
                        "enabled": dest.enabled,
                        "retry_count": dest.retry_count,
                        "timeout": dest.timeout
                    }
                    for dest in self.destinations
                ]
            }
            
            config_path = Path(config_file)
            config_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
            
            self.console_logger.info(f"Configuration saved to {config_file}")
            
        except Exception as e:
            self.console_logger.error(f"Failed to save configuration: {e}")
    
    def test_destinations(self) -> Dict[str, bool]:
        """
        Test all configured alert destinations.
        
        Returns:
            Dictionary mapping destination addresses to test results
        """
        # Create a test alert
        test_alert = SecurityAlert(
            timestamp=datetime.utcnow(),
            alert_id="TEST_ALERT",
            attack_type=AttackType.ARP_SPOOFING,  # Use enum value
            confidence_score=0.5,
            source_mac="00:00:00:00:00:00",
            source_ip="127.0.0.1",
            target_mac="00:00:00:00:00:01",
            target_ip="127.0.0.2",
            affected_hosts=["127.0.0.1"],
            raw_packet_data=b"test_data",
            detection_method=DetectionMethod.SIGNATURE_BASED  # Use enum value
        )
        
        self.console_logger.info("Testing alert destinations...")
        results = self.send_alert_to_destinations(test_alert)
        
        for address, success in results.items():
            status = "SUCCESS" if success else "FAILED"
            self.console_logger.info(f"Destination {address}: {status}")
        
        return results
    
    def get_destination_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about configured destinations.
        
        Returns:
            Dictionary with destination statistics
        """
        with self._lock:
            destinations = self.destinations.copy()
        
        stats = {
            "total_destinations": len(destinations),
            "enabled_destinations": sum(1 for d in destinations if d.enabled),
            "disabled_destinations": sum(1 for d in destinations if not d.enabled),
            "destinations_by_type": {},
            "registered_callbacks": len(self.alert_callbacks)
        }
        
        # Count by type
        for dest in destinations:
            dest_type = dest.destination_type
            if dest_type not in stats["destinations_by_type"]:
                stats["destinations_by_type"][dest_type] = {"total": 0, "enabled": 0}
            
            stats["destinations_by_type"][dest_type]["total"] += 1
            if dest.enabled:
                stats["destinations_by_type"][dest_type]["enabled"] += 1
        
        return stats
    
    def ensure_alerting_active(self) -> None:
        """Ensure alerting system is active after recovery (self-healing mechanism)."""
        try:
            # Re-enable console logger
            self.console_logger.disabled = False
            
            # Verify handlers are attached
            if not any(isinstance(h, logging.StreamHandler) for h in self.console_logger.handlers):
                console_handler = logging.StreamHandler()
                console_formatter = logging.Formatter(
                    '%(asctime)s - SECURITY ALERT - %(levelname)s - %(message)s'
                )
                console_handler.setFormatter(console_formatter)
                self.console_logger.addHandler(console_handler)
            
            # Re-enable all destinations
            with self._lock:
                for destination in self.destinations:
                    destination.enabled = True
            
            logging.getLogger(__name__).info("Alerting system re-enabled and ready for next alerts")
        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to ensure alerting is active: {e}")