#!/usr/bin/env python3
"""
Production entry point for the LAN Security System.

This script provides the production-ready command-line interface for running the
LAN Security System without attack simulation capabilities, focused purely on
real-world network security monitoring, detection, mitigation, and recovery.
"""

import argparse
import logging
import sys
from pathlib import Path

# Ensure current directory is in Python path (important for sudo execution)
sys.path.insert(0, str(Path(__file__).parent))

from lan_security_system.core.production_system import ProductionSecuritySystem
from lan_security_system.config.settings import SystemConfig
from lan_security_system.utils.logging_setup import setup_logging


def create_production_argument_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser for production deployment."""
    parser = argparse.ArgumentParser(
        description="LAN Security System - Production Deployment (No Attack Simulation)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Production Examples:
  %(prog)s --daemon --interface eth0       # Run as production daemon
  %(prog)s --config prod.yaml --daemon     # Use production config
  %(prog)s --status                        # Show production status
  %(prog)s --interactive                   # Production management console
        """
    )
    
    parser.add_argument(
        '--config', '-c',
        type=str,
        default='production_config.yaml',
        help='Production configuration file path (default: production_config.yaml)'
    )
    
    parser.add_argument(
        '--interface', '-i',
        type=str,
        required=True,
        help='Network interface to monitor (REQUIRED for production)'
    )
    
    parser.add_argument(
        '--daemon', '-d',
        action='store_true',
        help='Run in production daemon mode (recommended)'
    )
    
    parser.add_argument(
        '--interactive',
        action='store_true',
        help='Run production management console'
    )
    
    parser.add_argument(
        '--status',
        action='store_true',
        help='Show production system status and exit'
    )
    
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help='Production log level (default: INFO)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='LAN Security System v2.0.0 (Production)'
    )
    
    return parser


def run_production_daemon(system: ProductionSecuritySystem, interface: str) -> None:
    """Run the system in production daemon mode."""
    logger = logging.getLogger(__name__)
    logger.info("Starting LAN Security System in production daemon mode")
    
    try:
        # Start monitoring
        if not system.start_monitoring(interface):
            logger.error("Failed to start production monitoring")
            return
        
        logger.info(f"Production monitoring active on interface: {interface}")
        logger.info("System is now protecting your network from attacks")
        
        # Keep running until shutdown is requested
        import signal
        import time
        
        shutdown_requested = False
        
        def signal_handler(signum, frame):
            nonlocal shutdown_requested
            logger.info(f"Received signal {signum}, initiating production shutdown...")
            shutdown_requested = True
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        while not shutdown_requested:
            try:
                # Check system health periodically
                status = system.get_system_status()
                if status.get('system_state') == 'error':
                    logger.error("Production system in error state, attempting recovery...")
                
                # Sleep for monitoring interval
                time.sleep(30)
                
            except KeyboardInterrupt:
                logger.info("Received interrupt signal")
                break
            except Exception as e:
                logger.error(f"Error in production daemon mode: {e}")
                break
        
    finally:
        system.shutdown()


def run_production_interactive(system: ProductionSecuritySystem) -> None:
    """Run the system in production interactive mode."""
    print("LAN Security System - Production Management Console")
    print("Type 'help' for available commands, 'quit' to exit")
    
    while True:
        try:
            command = input("production> ").strip().lower()
            
            if command == 'quit' or command == 'exit':
                break
            elif command == 'help':
                print_production_help()
            elif command == 'status':
                print_production_status(system)
            elif command.startswith('start'):
                parts = command.split()
                interface = parts[1] if len(parts) > 1 else None
                if interface:
                    system.start_monitoring(interface)
                else:
                    print("Error: Interface required. Usage: start <interface>")
            elif command == 'stop':
                system.stop_monitoring()
            elif command == 'metrics':
                print_production_metrics(system)
            else:
                print(f"Unknown command: {command}. Type 'help' for available commands.")
                
        except KeyboardInterrupt:
            print("\\nReceived interrupt signal. Shutting down...")
            break
        except EOFError:
            print("\\nReceived EOF. Shutting down...")
            break
        except Exception as e:
            print(f"Error: {e}")
    
    system.shutdown()


def print_production_help() -> None:
    """Print help information for production interactive mode."""
    help_text = """
Production Commands:
  help                 - Show this help message
  status               - Show production system status
  start <interface>    - Start network monitoring on interface
  stop                 - Stop network monitoring
  metrics              - Show security metrics
  quit/exit            - Exit the production system
    """
    print(help_text)


def print_production_status(system: ProductionSecuritySystem) -> None:
    """Print current production system status."""
    status = system.get_system_status()
    print(f"\\nProduction System Status:")
    print(f"  State: {status.get('system_state', 'unknown')}")
    print(f"  Deployment Mode: {status.get('deployment_mode', 'unknown')}")
    print(f"  Monitoring Active: {status.get('monitoring_active', False)}")
    print(f"  Uptime: {status.get('uptime_formatted', 'unknown')}")
    
    metrics = status.get('metrics', {})
    print(f"\\nSecurity Metrics:")
    print(f"  Threats Detected: {metrics.get('total_alerts', 0)}")
    print(f"  Successful Mitigations: {metrics.get('successful_mitigations', 0)}")
    print(f"  Failed Mitigations: {metrics.get('failed_mitigations', 0)}")
    print(f"  Network Recoveries: {metrics.get('successful_recoveries', 0)}")


def print_production_metrics(system: ProductionSecuritySystem) -> None:
    """Print detailed production security metrics."""
    metrics = system.get_security_metrics()
    
    print(f"\\nProduction Security Metrics:")
    print(f"  Total Threats Detected: {metrics.get('total_threats_detected', 0)}")
    print(f"  Successful Mitigations: {metrics.get('successful_mitigations', 0)}")
    print(f"  Failed Mitigations: {metrics.get('failed_mitigations', 0)}")
    print(f"  Network Recoveries: {metrics.get('network_recoveries', 0)}")
    print(f"  System Uptime: {metrics.get('system_uptime_seconds', 0)} seconds")
    print(f"  Detection Accuracy: {metrics.get('detection_accuracy', 0):.1f}%")
    print(f"  Mitigation Success Rate: {metrics.get('mitigation_success_rate', 0):.1f}%")
    print(f"  Average Response Time: {metrics.get('average_response_time_ms', 0):.1f}ms")


def main() -> int:
    """Main entry point for the production LAN Security System."""
    parser = create_production_argument_parser()
    args = parser.parse_args()
    
    try:
        # Setup logging
        setup_logging(
            log_level=args.log_level,
            log_file='production_security.log',
            console_output=True
        )
        
        logger = logging.getLogger(__name__)
        logger.info("Starting Production LAN Security System")
        
        # Load production configuration
        config = SystemConfig()
        if Path(args.config).exists():
            import yaml
            with open(args.config, 'r') as f:
                config_data = yaml.safe_load(f)
            config.config_data = config_data
            logger.info(f"Loaded production configuration from {args.config}")
        else:
            logger.info("Using default production configuration")
        
        # Ensure production settings
        config.set('system.production_mode', True)
        config.set('system.simulation_mode', False)
        config.set('system.attack_simulation_enabled', False)
        config.set('logging.log_level', args.log_level)
        
        # Create production system
        system = ProductionSecuritySystem(config)
        
        # Initialize system
        if not system.initialize():
            print("Failed to initialize production system")
            return 1
        
        # Handle different run modes
        if args.status:
            # Show status and exit
            print_production_status(system)
            return 0
        
        elif args.interactive:
            # Run in interactive mode
            run_production_interactive(system)
        
        elif args.daemon:
            # Run in daemon mode
            run_production_daemon(system, args.interface)
        
        else:
            # Default to daemon mode for production
            print("Production system requires --daemon or --interactive mode")
            print("Run with --help for usage information")
            return 1
        
        return 0
        
    except KeyboardInterrupt:
        print("\\nInterrupted by user")
        return 130
    except Exception as e:
        print(f"Fatal error: {e}")
        logging.exception("Fatal error in production main")
        return 1


if __name__ == "__main__":
    sys.exit(main())