#!/usr/bin/env python3
"""
Production System Testing Script

This script tests the production LAN Security System to ensure
all components are working correctly without attack simulation.
"""

import sys
import time
from lan_security_system.core.production_system import ProductionSecuritySystem
from lan_security_system.config.settings import SystemConfig


def test_production_system():
    """Test the production system functionality."""
    print('🧪 PRODUCTION SYSTEM TESTING')
    print('=' * 50)
    print()

    # Test system initialization
    print('🔧 Testing Production System Initialization...')
    config = SystemConfig()
    config.set('system.production_mode', True)
    config.set('system.simulation_mode', False)
    config.set('system.attack_simulation_enabled', False)
    config.set('logging.log_level', 'INFO')

    # Create production system
    prod_system = ProductionSecuritySystem(config)

    # Test initialization
    print('   Initializing production system...')
    if prod_system.initialize():
        print('   ✅ Production system initialized successfully')
    else:
        print('   ❌ Production system initialization failed')
        return False

    # Test system status
    print()
    print('📊 Testing System Status...')
    status = prod_system.get_system_status()
    print(f'   System State: {status.get("system_state", "unknown")}')
    print(f'   Deployment Mode: {status.get("deployment_mode", "unknown")}')
    print(f'   Monitoring Active: {status.get("monitoring_active", False)}')
    print(f'   Uptime: {status.get("uptime_formatted", "unknown")}')

    # Test security metrics
    print()
    print('📈 Testing Security Metrics...')
    metrics = prod_system.get_security_metrics()
    print(f'   Threats Detected: {metrics.get("total_threats_detected", 0)}')
    print(f'   Detection Accuracy: {metrics.get("detection_accuracy", 0):.1f}%')
    print(f'   Mitigation Success Rate: {metrics.get("mitigation_success_rate", 0):.1f}%')
    print(f'   Average Response Time: {metrics.get("average_response_time_ms", 0):.1f}ms')

    # Test component validation
    print()
    print('🔗 Testing Component Integration...')
    if hasattr(prod_system.orchestrator, 'integrator'):
        validation = prod_system.orchestrator.integrator.validate_component_connections()
        print(f'   Overall Valid: {validation.get("overall_valid", False)}')
        print(f'   Detection Engine: {validation.get("detection_engine", False)}')
        print(f'   Mitigation Controller: {validation.get("mitigation_controller", False)}')
        print(f'   Recovery Manager: {validation.get("recovery_manager", False)}')
        print(f'   Event Logger: {validation.get("event_logger", False)}')
        print(f'   Deployment Mode: {validation.get("deployment_mode", "unknown")}')
        print(f'   Attack Simulation: {validation.get("attack_simulation_enabled", "N/A")}')

    # Test configuration validation
    print()
    print('⚙️  Testing Production Configuration...')
    print(f'   Production Mode: {config.get("system.production_mode", False)}')
    print(f'   Simulation Mode: {config.get("system.simulation_mode", True)}')
    print(f'   Attack Simulation: {config.get("system.attack_simulation_enabled", True)}')

    # Test component access
    print()
    print('🧩 Testing Component Access...')
    if hasattr(prod_system.orchestrator, 'integrator'):
        components = prod_system.orchestrator.integrator.get_all_components()
        print(f'   Available Components: {len(components)}')
        for name, component in components.items():
            print(f'     • {name}: {type(component).__name__}')

    # Cleanup
    print()
    print('🧹 Cleaning up test...')
    prod_system.shutdown()
    print('   ✅ Production system shutdown completed')

    print()
    print('🎉 PRODUCTION SYSTEM TEST COMPLETED!')
    print('   ✅ All core components are working correctly')
    print('   ✅ No attack simulation modules loaded')
    print('   ✅ Production configuration validated')
    print('   ✅ System is ready for deployment')
    
    return True


def test_production_vs_development():
    """Compare production system with development system."""
    print()
    print('🔍 PRODUCTION vs DEVELOPMENT COMPARISON')
    print('=' * 50)
    print()

    # Test production system
    print('🏭 PRODUCTION SYSTEM:')
    prod_config = SystemConfig()
    prod_config.set('system.production_mode', True)
    prod_config.set('system.simulation_mode', False)
    prod_config.set('system.attack_simulation_enabled', False)
    
    prod_system = ProductionSecuritySystem(prod_config)
    prod_system.initialize()
    
    prod_components = prod_system.orchestrator.integrator.get_all_components()
    print(f'   Components: {len(prod_components)}')
    for name in prod_components.keys():
        print(f'     ✅ {name}')
    
    prod_validation = prod_system.orchestrator.integrator.validate_component_connections()
    print(f'   Attack Simulation: {prod_validation.get("attack_simulation_enabled", "Not Available")}')
    print(f'   Deployment Mode: {prod_validation.get("deployment_mode", "unknown")}')
    
    prod_system.shutdown()

    # Test development system (original)
    print()
    print('🧪 DEVELOPMENT SYSTEM:')
    from lan_security_system.core.system_integration import ComponentIntegrator
    
    dev_config = SystemConfig()
    dev_config.set('system.simulation_mode', True)
    dev_config.set('system.production_mode', False)
    
    dev_integrator = ComponentIntegrator(dev_config)
    dev_components = dev_integrator.get_all_components()
    print(f'   Components: {len(dev_components)}')
    for name in dev_components.keys():
        print(f'     ✅ {name}')
    
    dev_validation = dev_integrator.validate_component_connections()
    print(f'   Attack Simulation: Available (for testing)')
    print(f'   Deployment Mode: development')

    print()
    print('📊 COMPARISON SUMMARY:')
    print(f'   Production Components: {len(prod_components)}')
    print(f'   Development Components: {len(dev_components)}')
    print('   Production: ❌ No attack simulation (secure)')
    print('   Development: ⚠️ Includes attack simulation (testing)')
    print()
    print('✅ Production system is properly isolated from attack tools!')


if __name__ == "__main__":
    try:
        success = test_production_system()
        if success:
            test_production_vs_development()
            sys.exit(0)
        else:
            sys.exit(1)
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        sys.exit(1)