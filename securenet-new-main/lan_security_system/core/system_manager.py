"""
System manager for configuration, initialization, and lifecycle management.

This module provides the main entry point and system management capabilities
for the LAN Security System, including configuration management, startup/shutdown
procedures, and component health monitoring.
"""

import argparse
import logging
import os
import signal
import sys
import yaml
from pathlib import Path
from typing import Dict, Any, Optional

from .system_orchestrator import SystemOrchestrator, SystemState
from ..config.settings import SystemConfig
from ..utils.logging_setup import setup_logging


logger = logging.getLogger(__name__)


class SystemManager:
    """
    Main system manager that handles configuration, initialization, and lifecycle management.
    
    This class serves as the primary entry point for the LAN Security System and provides:
    - Configuration file management
    - System startup and shutdown procedures
    - Component health monitoring and status reporting
    - Command-line interface for system control
    """
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or "config.yaml"
        self.config: Optional[SystemConfig] = None
        self.orchestrator: Optional[SystemOrchestrator] = None
        self._shutdown_requested = False
        
        # Setup signal handlers for graceful shutdown
        self._setup_signal_handlers()
    
    def load_configuration(self) -> bool:
        """Load system configuration from file or create default configuration."""
        try:
            config_path = Path(self.config_file)
            
            if config_path.exists():
                # Load configuration from file
                with open(config_path, 'r') as f:
                    config_data = yaml.safe_load(f)
                
                # Create SystemConfig with loaded data
                self.config = SystemConfig()
                self.config.config_data = config_data
                
                logger.info(f"Configuration loaded from {config_path}")
            else:
                # Create default configuration
                self.config = SystemConfig()
                self._save_default_configuration()
                logger.info(f"Created default configuration at {config_path}")
            
            # Setup logging based on configuration
            self._setup_logging()
            
            return True
            
        except Exception as e:
            print(f"Failed to load configuration: {e}")
            return False
    
    def _save_default_configuration(self) -> None:
        """Save default configuration to file."""
        try:
            config_path = Path(self.config_file)
            config_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(config_path, 'w') as f:
                yaml.dump(self.config.config_data, f, default_flow_style=False, indent=2)
            
            logger.info(f"Default configuration saved to {config_path}")
            
        except Exception as e:
            logger.error(f"Failed to save default configuration: {e}")
    
    def _setup_logging(self) -> None:
        """Setup logging based on configuration."""
        log_level = self.config.get('logging.log_level', 'INFO')
        log_file = self.config.get('logging.log_file', 'lan_security.log')
        console_output = self.config.get('logging.console_output', True)
        
        setup_logging(
            log_level=log_level,
            log_file=log_file,
            console_output=console_output
        )
    
    def initialize_system(self) -> bool:
        """Initialize the entire system."""
        try:
            if not self.config:
                logger.error("Configuration not loaded")
                return False
            
            logger.info("Initializing LAN Security System...")
            
            # Create system orchestrator
            self.orchestrator = SystemOrchestrator(self.config)
            
            # Initialize system components
            if not self.orchestrator.initialize_system():
                logger.error("System initialization failed")
                return False
            
            logger.info("System initialization completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"System initialization failed: {e}")
            return False
    
    def start_monitoring(self, interface: str = None) -> bool:
        """Start network monitoring."""
        try:
            if not self.orchestrator:
                logger.error("System not initialized")
                return False
            
            # Use configured interface or provided interface
            if not interface:
                interface = self.config.get('network.default_interface', 'eth0')
            
            logger.info(f"Starting network monitoring on interface: {interface}")
            
            if self.orchestrator.start_monitoring(interface):
                logger.info("Network monitoring started successfully")
                return True
            else:
                logger.error("Failed to start network monitoring")
                return False
                
        except Exception as e:
            logger.error(f"Failed to start monitoring: {e}")
            return False
    
    def stop_monitoring(self) -> bool:
        """Stop network monitoring."""
        try:
            if self.orchestrator:
                return self.orchestrator.stop_monitoring()
            return False
        except Exception as e:
            logger.error(f"Failed to stop monitoring: {e}")
            return False
    
    def shutdown_system(self) -> bool:
        """Gracefully shutdown the system."""
        try:
            logger.info("Shutting down LAN Security System...")
            
            if self.orchestrator:
                success = self.orchestrator.shutdown_system()
                if success:
                    logger.info("System shutdown completed successfully")
                else:
                    logger.error("System shutdown completed with errors")
                return success
            
            return True
            
        except Exception as e:
            logger.error(f"System shutdown failed: {e}")
            return False
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status."""
        if self.orchestrator:
            return self.orchestrator.get_system_status()
        else:
            return {
                'system_state': 'not_initialized',
                'error': 'System orchestrator not available'
            }
    
    def run_interactive_mode(self) -> None:
        """Run the system in interactive mode with command prompt."""
        print("LAN Security System - Interactive Mode")
        print("Type 'help' for available commands, 'quit' to exit")
        
        while not self._shutdown_requested:
            try:
                command = input("lan-security> ").strip().lower()
                
                if command == 'quit' or command == 'exit':
                    break
                elif command == 'help':
                    self._print_help()
                elif command == 'status':
                    self._print_status()
                elif command.startswith('start'):
                    parts = command.split()
                    interface = parts[1] if len(parts) > 1 else None
                    self.start_monitoring(interface)
                elif command == 'stop':
                    self.stop_monitoring()
                elif command == 'config':
                    self._print_configuration()
                elif command == 'metrics':
                    self._print_metrics()
                elif command == 'components':
                    self._print_component_status()
                else:
                    print(f"Unknown command: {command}. Type 'help' for available commands.")
                    
            except KeyboardInterrupt:
                print("\nReceived interrupt signal. Shutting down...")
                break
            except EOFError:
                print("\nReceived EOF. Shutting down...")
                break
            except Exception as e:
                print(f"Error: {e}")
        
        self.shutdown_system()
    
    def run_daemon_mode(self, interface: str = None) -> None:
        """Run the system in daemon mode."""
        logger.info("Starting LAN Security System in daemon mode")
        
        try:
            # Start monitoring
            if not self.start_monitoring(interface):
                logger.error("Failed to start monitoring in daemon mode")
                return
            
            # Keep running until shutdown is requested
            while not self._shutdown_requested:
                try:
                    # Check system health periodically
                    status = self.get_system_status()
                    if status.get('system_state') == 'error':
                        logger.error("System in error state, attempting recovery...")
                        # Could implement recovery logic here
                    
                    # Sleep for a short period
                    import time
                    time.sleep(10)
                    
                except KeyboardInterrupt:
                    logger.info("Received interrupt signal")
                    break
                except Exception as e:
                    logger.error(f"Error in daemon mode: {e}")
                    break
            
        finally:
            self.shutdown_system()
    
    def _setup_signal_handlers(self) -> None:
        """Setup signal handlers for graceful shutdown."""
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}, initiating shutdown...")
            self._shutdown_requested = True
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Windows doesn't have SIGHUP
        if hasattr(signal, 'SIGHUP'):
            signal.signal(signal.SIGHUP, signal_handler)
    
    def _print_help(self) -> None:
        """Print help information for interactive mode."""
        help_text = """
Available commands:
  help                 - Show this help message
  status               - Show system status
  start [interface]    - Start network monitoring (optionally specify interface)
  stop                 - Stop network monitoring
  config               - Show current configuration
  metrics              - Show system metrics
  components           - Show component status
  quit/exit            - Exit the system
        """
        print(help_text)
    
    def _print_status(self) -> None:
        """Print current system status."""
        status = self.get_system_status()
        print(f"\nSystem Status:")
        print(f"  State: {status.get('system_state', 'unknown')}")
        print(f"  Uptime: {status.get('uptime_formatted', 'unknown')}")
        
        metrics = status.get('metrics', {})
        print(f"\nMetrics:")
        print(f"  Total Alerts: {metrics.get('total_alerts', 0)}")
        print(f"  Successful Mitigations: {metrics.get('successful_mitigations', 0)}")
        print(f"  Failed Mitigations: {metrics.get('failed_mitigations', 0)}")
        print(f"  Successful Recoveries: {metrics.get('successful_recoveries', 0)}")
        print(f"  Failed Recoveries: {metrics.get('failed_recoveries', 0)}")
        print(f"  System Errors: {metrics.get('system_errors', 0)}")
    
    def _print_configuration(self) -> None:
        """Print current configuration."""
        if self.config:
            print("\nCurrent Configuration:")
            print(yaml.dump(self.config.config_data, default_flow_style=False, indent=2))
        else:
            print("Configuration not loaded")
    
    def _print_metrics(self) -> None:
        """Print detailed system metrics."""
        status = self.get_system_status()
        performance = status.get('performance_status', {})
        
        print(f"\nPerformance Status:")
        print(f"  State: {performance.get('state', 'unknown')}")
        
        current_metrics = performance.get('current_metrics', {})
        if current_metrics:
            print(f"  Packets Processed: {current_metrics.get('packets_processed', 0)}")
            print(f"  Alerts Generated: {current_metrics.get('alerts_generated', 0)}")
            print(f"  Processing Errors: {current_metrics.get('processing_errors', 0)}")
            print(f"  Average Detection Latency: {current_metrics.get('avg_detection_latency_ms', 0):.2f}ms")
            print(f"  CPU Usage: {current_metrics.get('cpu_usage_percent', 0):.1f}%")
            print(f"  Memory Usage: {current_metrics.get('memory_usage_mb', 0):.1f}MB")
    
    def _print_component_status(self) -> None:
        """Print component status information."""
        status = self.get_system_status()
        components = status.get('component_statuses', {})
        
        print(f"\nComponent Status:")
        for name, comp_status in components.items():
            print(f"  {name}:")
            print(f"    Health: {comp_status.get('health', 'unknown')}")
            print(f"    Error Count: {comp_status.get('error_count', 0)}")
            print(f"    Restart Count: {comp_status.get('restart_count', 0)}")
            print(f"    Last Heartbeat: {comp_status.get('last_heartbeat', 'never')}")
            if comp_status.get('last_error'):
                print(f"    Last Error: {comp_status.get('last_error')}")


def create_argument_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="LAN Security System - Network Attack Detection, Mitigation & Recovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --interactive                    # Run in interactive mode
  %(prog)s --daemon --interface eth0       # Run as daemon on eth0
  %(prog)s --config custom.yaml --daemon   # Use custom config file
  %(prog)s --status                        # Show system status and exit
        """
    )
    
    parser.add_argument(
        '--config', '-c',
        type=str,
        default='config.yaml',
        help='Configuration file path (default: config.yaml)'
    )
    
    parser.add_argument(
        '--interface', '-i',
        type=str,
        help='Network interface to monitor (default: from config)'
    )
    
    parser.add_argument(
        '--daemon', '-d',
        action='store_true',
        help='Run in daemon mode'
    )
    
    parser.add_argument(
        '--interactive',
        action='store_true',
        help='Run in interactive mode'
    )
    
    parser.add_argument(
        '--status',
        action='store_true',
        help='Show system status and exit'
    )
    
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help='Override log level from configuration'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='LAN Security System v1.0.0'
    )
    
    return parser


def main() -> int:
    """Main entry point for the LAN Security System."""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    try:
        # Create system manager
        system_manager = SystemManager(args.config)
        
        # Load configuration
        if not system_manager.load_configuration():
            print("Failed to load configuration")
            return 1
        
        # Override log level if specified
        if args.log_level:
            system_manager.config.set('logging.log_level', args.log_level)
            system_manager._setup_logging()
        
        # Initialize system
        if not system_manager.initialize_system():
            print("Failed to initialize system")
            return 1
        
        # Handle different run modes
        if args.status:
            # Show status and exit
            status = system_manager.get_system_status()
            print(f"System State: {status.get('system_state', 'unknown')}")
            print(f"Uptime: {status.get('uptime_formatted', 'unknown')}")
            return 0
        
        elif args.interactive:
            # Run in interactive mode
            system_manager.run_interactive_mode()
        
        elif args.daemon:
            # Run in daemon mode
            system_manager.run_daemon_mode(args.interface)
        
        else:
            # Default to interactive mode
            print("No mode specified. Use --daemon or --interactive")
            print("Run with --help for usage information")
            return 1
        
        return 0
        
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        return 130
    except Exception as e:
        print(f"Fatal error: {e}")
        logger.exception("Fatal error in main")
        return 1


if __name__ == "__main__":
    sys.exit(main())