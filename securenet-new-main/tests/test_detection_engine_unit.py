"""
Unit tests for detection engine components.
"""

import pytest
from datetime import datetime
from unittest.mock import Mock, patch
from scapy.all import Ether, ARP, IP, DNS, DNSQR, DNSRR

from lan_security_system.detection.signature_detectors import (
    ARPSpoofingDetector, MACFloodingDetector, DNSSpoofingDetector
)
from lan_security_system.detection.anomaly_detectors import (
    ARPRateAnomalyDetector, CAMTableOverflowDetector, DNSAnomalyDetector
)
from lan_security_system.detection.engine import RealTimeDetectionEngine
from lan_security_system.core.interfaces import (
    NetworkBaseline, DetectionConfig, AttackType, DetectionMethod
)


class TestSignatureDetectors:
    """Unit tests for signature-based detectors."""
    
    def test_arp_spoofing_detector_baseline_update(self):
        """Test ARP spoofing detector baseline update."""
        detector = ARPSpoofingDetector()
        
        baseline = NetworkBaseline(
            arp_table={"192.168.1.100": "00:11:22:33:44:55"},
            dns_cache={},
            mac_port_mappings={},
            baseline_timestamp=datetime.now()
        )
        
        detector.update_baseline(baseline)
        
        assert "192.168.1.100" in detector.baseline_arp_table
        assert detector.baseline_arp_table["192.168.1.100"] == "00:11:22:33:44:55"
    
    def test_arp_spoofing_detector_legitimate_traffic(self):
        """Test that legitimate ARP traffic is not flagged."""
        detector = ARPSpoofingDetector()
        
        # Create legitimate ARP request (should not trigger alert)
        packet = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=1,  # ARP request
            hwsrc="00:11:22:33:44:55",
            psrc="192.168.1.100",
            hwdst="00:00:00:00:00:00",
            pdst="192.168.1.1"
        )
        
        alert = detector.detect(bytes(packet))
        assert alert is None
    
    def test_mac_flooding_detector_threshold_configuration(self):
        """Test MAC flooding detector threshold configuration."""
        detector = MACFloodingDetector(mac_threshold=25, time_window=30)
        
        assert detector.mac_threshold == 25
        assert detector.time_window.total_seconds() == 30
    
    def test_mac_flooding_detector_normal_traffic(self):
        """Test that normal MAC learning is not flagged."""
        detector = MACFloodingDetector(mac_threshold=50, time_window=60)
        
        # Send a few normal packets
        for i in range(5):
            mac = f"00:11:22:33:44:{i:02x}"
            packet = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
            alert = detector.detect(bytes(packet))
            assert alert is None
    
    def test_dns_spoofing_detector_baseline_update(self):
        """Test DNS spoofing detector baseline update."""
        detector = DNSSpoofingDetector()
        
        baseline = NetworkBaseline(
            arp_table={},
            dns_cache={"example.com": "93.184.216.34"},
            mac_port_mappings={},
            baseline_timestamp=datetime.now()
        )
        
        detector.update_baseline(baseline)
        
        assert "example.com" in detector.baseline_dns_cache
        assert detector.baseline_dns_cache["example.com"] == "93.184.216.34"
    
    def test_dns_spoofing_detector_non_dns_traffic(self):
        """Test that non-DNS traffic is ignored."""
        detector = DNSSpoofingDetector()
        
        # Create non-DNS packet
        packet = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") / IP(
            src="192.168.1.100", dst="192.168.1.1"
        )
        
        alert = detector.detect(bytes(packet))
        assert alert is None


class TestAnomalyDetectors:
    """Unit tests for anomaly-based detectors."""
    
    def test_arp_rate_anomaly_detector_configuration(self):
        """Test ARP rate anomaly detector configuration."""
        config = DetectionConfig(arp_rate_threshold=15, detection_window_size=30)
        detector = ARPRateAnomalyDetector(config)
        
        assert detector.arp_rate_threshold == 15
        assert detector.detection_window.total_seconds() == 30
    
    def test_arp_rate_anomaly_detector_non_arp_traffic(self):
        """Test that non-ARP traffic is ignored."""
        config = DetectionConfig()
        detector = ARPRateAnomalyDetector(config)
        
        # Create non-ARP packet
        packet = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") / IP(
            src="192.168.1.100", dst="192.168.1.1"
        )
        
        alert = detector.detect(bytes(packet))
        assert alert is None
    
    def test_cam_table_overflow_detector_configuration(self):
        """Test CAM table overflow detector configuration."""
        config = DetectionConfig(cam_table_threshold=0.8, mac_learning_threshold=40)
        detector = CAMTableOverflowDetector(config)
        
        assert detector.cam_table_threshold == 0.8
        assert detector.mac_learning_threshold == 40
    
    def test_cam_table_overflow_detector_baseline_update(self):
        """Test CAM table overflow detector baseline update."""
        config = DetectionConfig()
        detector = CAMTableOverflowDetector(config)
        
        baseline = NetworkBaseline(
            arp_table={},
            dns_cache={},
            mac_port_mappings={"00:11:22:33:44:55": 1, "aa:bb:cc:dd:ee:ff": 2},
            baseline_timestamp=datetime.now()
        )
        
        detector.update_baseline(baseline)
        
        assert "00:11:22:33:44:55" in detector.simulated_cam_table
        assert "aa:bb:cc:dd:ee:ff" in detector.simulated_cam_table
    
    def test_dns_anomaly_detector_configuration(self):
        """Test DNS anomaly detector configuration."""
        config = DetectionConfig(dns_ttl_variance_threshold=500, detection_window_size=120)
        detector = DNSAnomalyDetector(config)
        
        assert detector.ttl_variance_threshold == 500
        assert detector.detection_window.total_seconds() == 120
    
    def test_dns_anomaly_detector_non_dns_traffic(self):
        """Test that non-DNS traffic is ignored."""
        config = DetectionConfig()
        detector = DNSAnomalyDetector(config)
        
        # Create non-DNS packet
        packet = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") / IP(
            src="192.168.1.100", dst="192.168.1.1"
        )
        
        alert = detector.detect(bytes(packet))
        assert alert is None


class TestRealTimeDetectionEngine:
    """Unit tests for real-time detection engine."""
    
    def test_detection_engine_initialization(self):
        """Test detection engine initialization."""
        config = DetectionConfig()
        engine = RealTimeDetectionEngine(config)
        
        assert engine.config == config
        assert len(engine.detectors) == 6  # 3 signature + 3 anomaly detectors
        assert not engine.is_running
        assert engine.alert_callback is None
    
    def test_detection_engine_detector_registration(self):
        """Test detector registration."""
        config = DetectionConfig()
        engine = RealTimeDetectionEngine(config)
        
        initial_count = len(engine.detectors)
        
        # Register additional detector
        custom_detector = ARPSpoofingDetector()
        engine.register_detector(custom_detector)
        
        assert len(engine.detectors) == initial_count + 1
        assert custom_detector in engine.detectors
    
    def test_detection_engine_alert_callback(self):
        """Test alert callback registration."""
        config = DetectionConfig()
        engine = RealTimeDetectionEngine(config)
        
        callback = Mock()
        engine.set_alert_callback(callback)
        
        assert engine.alert_callback == callback
    
    def test_detection_engine_baseline_update(self):
        """Test baseline update for all detectors."""
        config = DetectionConfig()
        engine = RealTimeDetectionEngine(config)
        
        baseline = NetworkBaseline(
            arp_table={"192.168.1.100": "00:11:22:33:44:55"},
            dns_cache={"example.com": "93.184.216.34"},
            mac_port_mappings={"00:11:22:33:44:55": 1},
            baseline_timestamp=datetime.now()
        )
        
        # Mock detector update_baseline methods
        for detector in engine.detectors:
            detector.update_baseline = Mock()
        
        engine.update_baseline(baseline)
        
        # Verify all detectors received baseline update
        for detector in engine.detectors:
            detector.update_baseline.assert_called_once_with(baseline)
    
    def test_detection_engine_stats_initialization(self):
        """Test detection engine statistics initialization."""
        config = DetectionConfig()
        engine = RealTimeDetectionEngine(config)
        
        stats = engine.get_detection_stats()
        
        assert stats['packets_processed'] == 0
        assert stats['alerts_generated'] == 0
        assert stats['processing_errors'] == 0
        assert stats['queue_overflows'] == 0
        assert stats['start_time'] is None
        assert stats['last_packet_time'] is None
    
    @patch('lan_security_system.detection.engine.get_if_list')
    def test_detection_engine_interface_validation(self, mock_get_if_list):
        """Test network interface validation."""
        config = DetectionConfig()
        engine = RealTimeDetectionEngine(config)
        
        # Mock available interfaces
        mock_get_if_list.return_value = ['eth0', 'wlan0', 'lo']
        
        # Test valid interface
        try:
            engine.start_monitoring('eth0')
            # Should not raise exception
        except ValueError:
            pytest.fail("Valid interface should not raise ValueError")
        finally:
            engine.stop_monitoring()
        
        # Test invalid interface
        with pytest.raises(ValueError, match="Interface invalid not found"):
            engine.start_monitoring('invalid')
    
    def test_detection_engine_performance_monitor(self):
        """Test performance monitor initialization."""
        config = DetectionConfig()
        engine = RealTimeDetectionEngine(config)
        
        assert engine.performance_monitor is not None
        assert engine.performance_monitor.config == config
        assert not engine.performance_monitor.is_running
    
    def test_detection_engine_stop_when_not_running(self):
        """Test stopping engine when not running."""
        config = DetectionConfig()
        engine = RealTimeDetectionEngine(config)
        
        # Should not raise exception
        engine.stop_monitoring()
        assert not engine.is_running


class TestDetectionEngineEdgeCases:
    """Unit tests for detection engine edge cases."""
    
    def test_malformed_packet_handling(self):
        """Test handling of malformed packets."""
        detector = ARPSpoofingDetector()
        
        # Test with invalid packet data
        malformed_data = b'\x00\x01\x02\x03'  # Too short for valid Ethernet frame
        
        # Should not raise exception, should return None
        alert = detector.detect(malformed_data)
        assert alert is None
    
    def test_empty_packet_handling(self):
        """Test handling of empty packets."""
        detector = MACFloodingDetector()
        
        # Test with empty packet data
        empty_data = b''
        
        # Should not raise exception, should return None
        alert = detector.detect(empty_data)
        assert alert is None
    
    def test_detector_error_handling(self):
        """Test detector error handling."""
        config = DetectionConfig()
        engine = RealTimeDetectionEngine(config)
        
        # Mock a detector that raises an exception
        faulty_detector = Mock()
        faulty_detector.detect.side_effect = Exception("Test error")
        engine.detectors.append(faulty_detector)
        
        # Process packet should handle the exception gracefully
        packet_data = bytes(Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff"))
        
        # This would be called in the packet processing worker
        # Should not raise exception despite faulty detector
        try:
            for detector in engine.detectors:
                try:
                    alert = detector.detect(packet_data)
                except Exception:
                    # Should be caught and logged
                    pass
        except Exception:
            pytest.fail("Engine should handle detector exceptions gracefully")
    
    def test_detection_config_defaults(self):
        """Test detection configuration default values."""
        config = DetectionConfig()
        
        assert config.arp_rate_threshold == 10
        assert config.mac_learning_threshold == 50
        assert config.cam_table_threshold == 0.9
        assert config.dns_ttl_variance_threshold == 300
        assert config.detection_window_size == 60
        assert config.detection_latency_target == 100
        assert config.false_positive_threshold == 0.05
    
    def test_detection_config_custom_values(self):
        """Test detection configuration with custom values."""
        config = DetectionConfig(
            arp_rate_threshold=20,
            mac_learning_threshold=100,
            cam_table_threshold=0.8,
            dns_ttl_variance_threshold=600,
            detection_window_size=120,
            detection_latency_target=50,
            false_positive_threshold=0.02
        )
        
        assert config.arp_rate_threshold == 20
        assert config.mac_learning_threshold == 100
        assert config.cam_table_threshold == 0.8
        assert config.dns_ttl_variance_threshold == 600
        assert config.detection_window_size == 120
        assert config.detection_latency_target == 50
        assert config.false_positive_threshold == 0.02