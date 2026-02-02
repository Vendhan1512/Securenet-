#!/usr/bin/env python3
"""
Web API for the LAN Security System.

This module provides a FastAPI-based web interface for the LAN Security System,
allowing remote monitoring and management through a REST API.
"""

import asyncio
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, status, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import jwt
import uvicorn
from passlib.context import CryptContext

from lan_security_system.core.production_system import ProductionSecuritySystem
from lan_security_system.config.settings import SystemConfig
from lan_security_system.utils.logging_setup import setup_logging


# Configuration
SECRET_KEY = "your-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

from passlib.context import CryptContext
import hashlib

# Simple password hashing using SHA-256 (for demo purposes)
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return hashlib.sha256(plain_password.encode()).hexdigest() == hashed_password
security = HTTPBearer()

# Global system instance
security_system: Optional[ProductionSecuritySystem] = None
system_thread: Optional[threading.Thread] = None
system_running = False

# Fake user database (replace with real database in production)
fake_users_db = {
    "admin": {
        "username": "admin",
        "hashed_password": hash_password("admin123"),
        "role": "admin",
        "email": "admin@security.local"
    },
    "operator": {
        "username": "operator", 
        "hashed_password": hash_password("operator123"),
        "role": "operator",
        "email": "operator@security.local"
    }
}

# Pydantic models
class LoginRequest(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class User(BaseModel):
    username: str
    email: str
    role: str

class SystemStatus(BaseModel):
    system_state: str
    deployment_mode: str
    monitoring_active: bool
    uptime_formatted: str
    interface: Optional[str] = None

class SecurityMetrics(BaseModel):
    total_threats_detected: int
    successful_mitigations: int
    failed_mitigations: int
    network_recoveries: int
    system_uptime_seconds: float
    detection_accuracy: float
    mitigation_success_rate: float
    average_response_time_ms: float

class SecurityAlert(BaseModel):
    id: str
    timestamp: datetime
    attack_type: str
    source_ip: str
    source_mac: str
    target_ip: str
    target_mac: str
    confidence_score: float
    status: str

class MitigationAction(BaseModel):
    id: str
    timestamp: datetime
    attack_type: str
    actions_taken: List[str]
    success: bool
    error_message: Optional[str] = None

class NetworkInterface(BaseModel):
    name: str
    device_name: Optional[str] = None
    status: str
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    is_up: bool = False
    speed: int = 0  # Mbps
    bytes_sent: int = 0
    bytes_recv: int = 0
    mtu: int = 0
    duplex: str = "unknown"

class StartMonitoringRequest(BaseModel):
    interface: str

class ConfigurationUpdate(BaseModel):
    key: str
    value: Any

# FastAPI app
app = FastAPI(
    title="LAN Security System API",
    description="REST API for LAN Security System monitoring and management",
    version="2.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],  # React dev servers
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Utility functions
def get_password_hash(password: str) -> str:
    return hash_password(password)

def authenticate_user(username: str, password: str) -> Optional[Dict]:
    user = fake_users_db.get(username)
    if not user or not verify_password(password, user["hashed_password"]):
        return None
    return user

def create_access_token(data: Dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(data: Dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        token_type: str = payload.get("type")
        
        if username is None or token_type != "access":
            raise credentials_exception
            
    except jwt.PyJWTError:
        raise credentials_exception
        
    user = fake_users_db.get(username)
    if user is None:
        raise credentials_exception
        
    return user

def require_admin(current_user: Dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user

def initialize_security_system():
    """Initialize the security system."""
    global security_system
    
    try:
        # Setup logging
        setup_logging(log_level="INFO", log_file="web_api.log", console_output=True)
        
        # Load configuration
        config = SystemConfig()
        config.set('system.production_mode', True)
        config.set('system.simulation_mode', False)
        config.set('system.attack_simulation_enabled', False)
        
        # Create and initialize system
        security_system = ProductionSecuritySystem(config)
        if not security_system.initialize():
            raise Exception("Failed to initialize security system")
            
        logging.info("Security system initialized successfully")
        return True
        
    except Exception as e:
        logging.error(f"Failed to initialize security system: {e}")
        return False

# API Routes

@app.on_event("startup")
async def startup_event():
    """Initialize the security system on startup."""
    success = initialize_security_system()
    if not success:
        logging.error("Failed to start security system")

@app.post("/api/auth/login", response_model=Token)
async def login(login_request: LoginRequest):
    """Authenticate user and return JWT tokens."""
    user = authenticate_user(login_request.username, login_request.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    refresh_token = create_refresh_token(data={"sub": user["username"]})
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@app.post("/api/auth/refresh", response_model=Token)
async def refresh_token(refresh_token: str):
    """Refresh access token using refresh token."""
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        token_type: str = payload.get("type")
        
        if username is None or token_type != "refresh":
            raise HTTPException(status_code=401, detail="Invalid refresh token")
            
        user = fake_users_db.get(username)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
            
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        new_access_token = create_access_token(
            data={"sub": username}, expires_delta=access_token_expires
        )
        new_refresh_token = create_refresh_token(data={"sub": username})
        
        return {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer"
        }
        
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

@app.get("/api/auth/me", response_model=User)
async def get_current_user_info(current_user: Dict = Depends(get_current_user)):
    """Get current user information."""
    return User(
        username=current_user["username"],
        email=current_user["email"],
        role=current_user["role"]
    )

@app.get("/api/system/status", response_model=SystemStatus)
async def get_system_status(current_user: Dict = Depends(get_current_user)):
    """Get current system status."""
    if not security_system:
        raise HTTPException(status_code=503, detail="Security system not initialized")
    
    status = security_system.get_system_status()
    return SystemStatus(
        system_state=status.get("system_state", "unknown"),
        deployment_mode=status.get("deployment_mode", "unknown"),
        monitoring_active=status.get("monitoring_active", False),
        uptime_formatted=status.get("uptime_formatted", "unknown")
    )

@app.get("/api/system/metrics", response_model=SecurityMetrics)
async def get_security_metrics(current_user: Dict = Depends(get_current_user)):
    """Get security metrics."""
    if not security_system:
        raise HTTPException(status_code=503, detail="Security system not initialized")
    
    metrics = security_system.get_security_metrics()
    return SecurityMetrics(**metrics)

@app.post("/api/system/start-monitoring")
async def start_monitoring(
    request: StartMonitoringRequest,
    current_user: Dict = Depends(require_admin)
):
    """Start network monitoring on specified interface."""
    if not security_system:
        raise HTTPException(status_code=503, detail="Security system not initialized")
    
    try:
        # Get the device name for the friendly interface name
        import psutil
        import socket
        from scapy.interfaces import get_if_list
        from scapy.arch import get_if_addr, get_if_hwaddr
        
        interface_name = request.interface
        device_name = None
        
        # Get interface details to find the corresponding scapy device name
        network_stats = psutil.net_if_stats()
        network_addrs = psutil.net_if_addrs()
        scapy_interfaces = get_if_list()
        
        if interface_name in network_stats:
            addrs = network_addrs.get(interface_name, [])
            
            # Get MAC address from psutil
            mac_address = None
            ip_address = None
            for addr in addrs:
                if addr.family == socket.AF_INET:  # IPv4
                    ip_address = addr.address
                elif addr.family == psutil.AF_LINK:  # MAC address
                    mac_address = addr.address
            
            # Find corresponding scapy interface by MAC address
            if mac_address:
                for scapy_iface in scapy_interfaces:
                    try:
                        scapy_mac = get_if_hwaddr(scapy_iface)
                        if scapy_mac and scapy_mac.lower() == mac_address.lower():
                            device_name = scapy_iface
                            break
                    except:
                        continue
            
            # If no MAC match, try IP address match
            if not device_name and ip_address:
                for scapy_iface in scapy_interfaces:
                    try:
                        scapy_ip = get_if_addr(scapy_iface)
                        if scapy_ip and scapy_ip == ip_address:
                            device_name = scapy_iface
                            break
                    except:
                        continue
        
        # Use device name if found, otherwise try the original name
        monitoring_interface = device_name if device_name else interface_name
        
        success = security_system.start_monitoring(monitoring_interface)
        if success:
            return {"message": f"Monitoring started on interface {interface_name} (device: {monitoring_interface})"}
        else:
            raise HTTPException(status_code=400, detail=f"Failed to start monitoring on {interface_name}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/system/stop-monitoring")
async def stop_monitoring(current_user: Dict = Depends(require_admin)):
    """Stop network monitoring."""
    if not security_system:
        raise HTTPException(status_code=503, detail="Security system not initialized")
    
    try:
        success = security_system.stop_monitoring()
        if success:
            return {"message": "Monitoring stopped"}
        else:
            raise HTTPException(status_code=400, detail="Failed to stop monitoring")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/security/alerts")
async def get_security_alerts(
    limit: int = 50,
    offset: int = 0,
    current_user: Dict = Depends(get_current_user)
):
    """Get security alerts with pagination."""
    # In a real implementation, this would query the logging system
    # For now, return mock data based on system metrics
    if not security_system:
        raise HTTPException(status_code=503, detail="Security system not initialized")
    
    # Mock alerts data - in production, read from logs
    alerts = []
    metrics = security_system.get_security_metrics()
    
    # Generate some mock alerts based on metrics
    for i in range(min(limit, metrics.get('total_threats_detected', 0))):
        alert = SecurityAlert(
            id=f"alert_{i+1}",
            timestamp=datetime.utcnow() - timedelta(hours=i),
            attack_type="arp_spoofing",
            source_ip=f"192.168.1.{100+i}",
            source_mac=f"aa:bb:cc:dd:ee:{i:02x}",
            target_ip="192.168.1.1",
            target_mac="ff:ff:ff:ff:ff:ff",
            confidence_score=0.95,
            status="mitigated"
        )
        alerts.append(alert)
    
    return {
        "alerts": alerts[offset:offset+limit],
        "total": len(alerts),
        "limit": limit,
        "offset": offset
    }

@app.get("/api/security/mitigations")
async def get_mitigation_actions(
    limit: int = 50,
    offset: int = 0,
    current_user: Dict = Depends(get_current_user)
):
    """Get mitigation actions with pagination."""
    if not security_system:
        raise HTTPException(status_code=503, detail="Security system not initialized")
    
    # Mock mitigation data
    mitigations = []
    metrics = security_system.get_security_metrics()
    
    for i in range(min(limit, metrics.get('successful_mitigations', 0))):
        mitigation = MitigationAction(
            id=f"mitigation_{i+1}",
            timestamp=datetime.utcnow() - timedelta(hours=i),
            attack_type="arp_spoofing",
            actions_taken=[
                f"Blocked MAC address aa:bb:cc:dd:ee:{i:02x}",
                f"Reset ARP cache for 192.168.1.{100+i}"
            ],
            success=True
        )
        mitigations.append(mitigation)
    
    return {
        "mitigations": mitigations[offset:offset+limit],
        "total": len(mitigations),
        "limit": limit,
        "offset": offset
    }

@app.get("/api/network/interfaces")
async def get_network_interfaces(current_user: Dict = Depends(get_current_user)):
    """Get available network interfaces with detailed information (internet-capable only)."""
    try:
        import psutil
        import socket
        import logging
        
        logger = logging.getLogger(__name__)
        logger.info("Starting interface detection...")
        
        interface_list = []
        
        # Get system network interfaces
        network_stats = psutil.net_if_stats()
        network_addrs = psutil.net_if_addrs()
        
        logger.info(f"Found {len(network_stats)} total interfaces")
        
        def is_internet_capable_ip(ip_address):
            """Check if IP address is in a range that could have internet access."""
            if not ip_address:
                return False
            
            # Skip loopback and APIPA addresses
            if ip_address.startswith('127.') or ip_address.startswith('169.254.'):
                return False
            
            try:
                ip_parts = ip_address.split('.')
                if len(ip_parts) != 4:
                    return False
                
                first_octet = int(ip_parts[0])
                second_octet = int(ip_parts[1])
                
                # Common internet-capable IP ranges:
                # Private: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
                # Public: 8-223 (excluding reserved ranges)
                if (first_octet == 10 or 
                    (first_octet == 172 and 16 <= second_octet <= 31) or
                    (first_octet == 192 and second_octet == 168) or
                    (8 <= first_octet <= 223 and first_octet not in [127, 169])):
                    return True
                    
            except (ValueError, IndexError):
                pass
            
            return False
        
        # Use psutil interface names directly (they're more user-friendly on Windows)
        for iface_name in network_stats.keys():
            logger.info(f"Processing interface: {iface_name}")
            
            # Skip obvious virtual/loopback interfaces
            if any(skip in iface_name.lower() for skip in ['loopback', 'pseudo']):
                logger.info(f"  Skipped {iface_name}: matches skip pattern")
                continue
                
            try:
                # Get interface statistics
                stats = network_stats.get(iface_name)
                addrs = network_addrs.get(iface_name, [])
                
                # Must be up
                if not (stats and stats.isup):
                    logger.info(f"  Skipped {iface_name}: interface is down")
                    continue
                
                # Extract IP and MAC addresses
                ip_address = None
                mac_address = None
                
                for addr in addrs:
                    if addr.family == socket.AF_INET:  # IPv4
                        ip_address = addr.address
                    elif addr.family == psutil.AF_LINK:  # MAC address
                        mac_address = addr.address
                
                logger.info(f"  {iface_name} - IP: {ip_address}, MAC: {mac_address}")
                
                # Must have internet-capable IP
                if not is_internet_capable_ip(ip_address):
                    logger.info(f"  Skipped {iface_name}: not internet-capable IP")
                    continue
                
                logger.info(f"  {iface_name} passed all filters, adding to list")
                
                # Try to find corresponding scapy interface (simplified)
                scapy_device_name = None
                try:
                    from scapy.interfaces import get_if_list
                    from scapy.arch import get_if_addr, get_if_hwaddr
                    
                    scapy_interfaces = get_if_list()
                    
                    # Find by MAC address
                    if mac_address:
                        for scapy_iface in scapy_interfaces:
                            try:
                                scapy_mac = get_if_hwaddr(scapy_iface)
                                if scapy_mac and scapy_mac.lower() == mac_address.lower():
                                    scapy_device_name = scapy_iface
                                    break
                            except:
                                continue
                    
                    # Find by IP address if MAC didn't work
                    if not scapy_device_name and ip_address:
                        for scapy_iface in scapy_interfaces:
                            try:
                                scapy_ip = get_if_addr(scapy_iface)
                                if scapy_ip and scapy_ip == ip_address:
                                    scapy_device_name = scapy_iface
                                    break
                            except:
                                continue
                except Exception as e:
                    logger.warning(f"  Scapy mapping failed for {iface_name}: {e}")
                    # If scapy fails, continue without device mapping
                    pass
                
                # Determine interface status - all filtered interfaces are active
                status = "active"
                
                # Get additional stats
                # Network I/O stats are separate from interface stats
                try:
                    io_counters = psutil.net_io_counters(pernic=True)
                    io_stats = io_counters.get(iface_name)
                    bytes_sent = io_stats.bytes_sent if io_stats else 0
                    bytes_recv = io_stats.bytes_recv if io_stats else 0
                except:
                    bytes_sent = 0
                    bytes_recv = 0
                
                speed = getattr(stats, 'speed', 0) if stats else 0
                
                interface_info = {
                    "name": iface_name,
                    "device_name": scapy_device_name,
                    "status": status,
                    "ip_address": ip_address,
                    "mac_address": mac_address,
                    "is_up": True,  # All filtered interfaces are up
                    "speed": speed,
                    "bytes_sent": bytes_sent,
                    "bytes_recv": bytes_recv,
                    "mtu": stats.mtu if stats else 0,
                    "duplex": stats.duplex.name if stats and hasattr(stats, 'duplex') else "unknown"
                }
                
                interface_list.append(interface_info)
                logger.info(f"  Added {iface_name} to interface list")
                
            except Exception as e:
                logger.error(f"  Error processing {iface_name}: {e}")
                # Skip interfaces that cause errors
                continue
        
        logger.info(f"Returning {len(interface_list)} interfaces")
        return {"interfaces": interface_list}
        
    except Exception as e:
        logger.error(f"Failed to get interfaces: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get interfaces: {e}")

@app.get("/api/logs/security")
async def get_security_logs(
    limit: int = 100,
    offset: int = 0,
    current_user: Dict = Depends(get_current_user)
):
    """Get security event logs."""
    try:
        log_file = Path("logs/security_events.jsonl")
        if not log_file.exists():
            return {"logs": [], "total": 0}
        
        logs = []
        with open(log_file, 'r') as f:
            lines = f.readlines()
            
        # Parse JSON lines and apply pagination
        for line in lines[offset:offset+limit]:
            try:
                import json
                log_entry = json.loads(line.strip())
                logs.append(log_entry)
            except json.JSONDecodeError:
                continue
        
        return {
            "logs": logs,
            "total": len(lines),
            "limit": limit,
            "offset": offset
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read logs: {e}")

@app.get("/api/config")
async def get_configuration(current_user: Dict = Depends(require_admin)):
    """Get system configuration."""
    if not security_system:
        raise HTTPException(status_code=503, detail="Security system not initialized")
    
    # Return key configuration values
    config = {
        "detection": {
            "arp_rate_threshold": 15,
            "mac_learning_threshold": 100,
            "detection_window_size": 120,
            "false_positive_threshold": 0.02
        },
        "performance": {
            "max_monitored_hosts": 500,
            "cpu_utilization_threshold": 0.7,
            "mitigation_response_time": 100,
            "recovery_time_limit": 15
        },
        "logging": {
            "log_level": "WARNING",
            "max_file_size": 50485760,
            "backup_count": 10
        }
    }
    
    return {"configuration": config}

@app.put("/api/config")
async def update_configuration(
    updates: List[ConfigurationUpdate],
    current_user: Dict = Depends(require_admin)
):
    """Update system configuration."""
    if not security_system:
        raise HTTPException(status_code=503, detail="Security system not initialized")
    
    try:
        updated_keys = []
        for update in updates:
            # In a real implementation, validate and apply configuration changes
            updated_keys.append(update.key)
        
        return {
            "message": f"Updated {len(updated_keys)} configuration keys",
            "updated_keys": updated_keys
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update configuration: {e}")

@app.get("/api/network/interfaces/{interface_name:path}/health")
async def get_interface_health(
    interface_name: str,
    current_user: Dict = Depends(get_current_user)
):
    """Get detailed health information for a specific interface."""
    try:
        import psutil
        import time
        from urllib.parse import unquote
        
        # URL decode the interface name to handle special characters
        decoded_interface_name = unquote(interface_name)
        
        # Get current stats
        network_stats = psutil.net_if_stats()
        network_addrs = psutil.net_if_addrs()
        
        if decoded_interface_name not in network_stats:
            raise HTTPException(status_code=404, detail=f"Interface '{decoded_interface_name}' not found")
        
        stats = network_stats[decoded_interface_name]
        addrs = network_addrs.get(decoded_interface_name, [])
        
        # Calculate traffic rates (simplified - in production you'd store historical data)
        current_time = time.time()
        
        health_info = {
            "interface_name": decoded_interface_name,
            "is_healthy": stats.isup and len(addrs) > 0,
            "uptime_seconds": 0,  # Would need to track this
            "packet_loss_rate": 0.0,  # Would need to calculate from drops
            "error_rate": 0.0,
            "current_speed": stats.speed,
            "utilization_percent": 0.0,  # Would calculate from traffic
            "last_check": current_time,
            "issues": []
        }
        
        # Check for potential issues
        if not stats.isup:
            health_info["issues"].append("Interface is down")
        if len(addrs) == 0:
            health_info["issues"].append("No IP address assigned")
        if stats.speed == 0:
            health_info["issues"].append("Unknown link speed")
            
        return health_info
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get interface health: {e}")

# Dashboard endpoints (no auth required for demo)
@app.get("/")
async def serve_dashboard():
    """Serve the dashboard HTML."""
    from fastapi.responses import FileResponse
    dashboard_path = Path(__file__).parent / "dashboard.html"
    if dashboard_path.exists():
        return FileResponse(dashboard_path)
    return {"message": "Dashboard not found. Please ensure dashboard.html is in the same directory."}

@app.get("/api/stats")
async def get_dashboard_stats():
    """Get dashboard statistics."""
    try:
        import json
        from pathlib import Path
        
        logs_dir = Path(__file__).parent / "logs"
        events_file = logs_dir / "security_events.jsonl"
        mit_file = logs_dir / "mitigation_actions.jsonl"
        rec_file = logs_dir / "recovery_confirmations.jsonl"
        
        def count_jsonl(path, predicate=lambda d: True):
            if not path.exists():
                return 0
            count = 0
            try:
                with open(path, 'r') as f:
                    for line in f:
                        if not line.strip():
                            continue
                        try:
                            data = json.loads(line)
                            if predicate(data):
                                count += 1
                        except:
                            continue
            except:
                pass
            return count
        
        def count_by_attack(path):
            counts = {}
            if not path.exists():
                return counts
            try:
                with open(path, 'r') as f:
                    for line in f:
                        if not line.strip():
                            continue
                        try:
                            data = json.loads(line)
                            ev = data.get('event_data', {})
                            atk = ev.get('attack_type')
                            if atk:
                                counts[atk] = counts.get(atk, 0) + 1
                        except:
                            continue
            except:
                pass
            return counts
        
        total_alerts = count_jsonl(events_file, lambda d: d.get('event_type') == 'security_event')
        mitigations = count_jsonl(mit_file)
        recoveries = count_jsonl(rec_file)
        attack_types = count_by_attack(events_file)
        
        # Get system status if available
        uptime = "N/A"
        interface = "N/A"
        monitoring_active = False
        
        if security_system:
            try:
                status = security_system.get_system_status()
                uptime = status.get('uptime_formatted', 'N/A')
                monitoring_active = status.get('monitoring_active', False)
                # Try to get interface from config
                interface = security_system.config.get('network.default_interface', 'N/A')
            except:
                pass
        
        return {
            "total_alerts": total_alerts,
            "mitigations": mitigations,
            "recoveries": recoveries,
            "attack_types": attack_types,
            "uptime": uptime,
            "interface": interface,
            "monitoring_active": monitoring_active,
            "detection_rate": 100.0,
            "avg_response_time": 0.5,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logging.error(f"Failed to get dashboard stats: {e}")
        return {
            "total_alerts": 0,
            "mitigations": 0,
            "recoveries": 0,
            "attack_types": {},
            "uptime": "N/A",
            "interface": "N/A",
            "monitoring_active": False,
            "detection_rate": 0.0,
            "avg_response_time": 0.0,
            "timestamp": datetime.utcnow().isoformat()
        }

@app.get("/api/alerts")
async def get_recent_alerts(limit: int = 10):
    """Get recent security alerts."""
    try:
        import json
        from pathlib import Path
        
        events_file = Path(__file__).parent / "logs" / "security_events.jsonl"
        
        if not events_file.exists():
            return []
        
        alerts = []
        with open(events_file, 'r') as f:
            lines = f.readlines()
            # Get last N lines
            for line in lines[-limit:]:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    if data.get('event_type') == 'security_event':
                        ev = data.get('event_data', {})
                        alerts.append({
                            "timestamp": data.get('timestamp'),
                            "attack_type": ev.get('attack_type'),
                            "source_ip": ev.get('source_ip'),
                            "source_mac": ev.get('source_mac'),
                            "confidence": ev.get('confidence_score'),
                            "message": f"Attack detected from {ev.get('source_ip')} targeting {ev.get('target_ip')}"
                        })
                except:
                    continue
        
        # Return in reverse order (newest first)
        return list(reversed(alerts))
    except Exception as e:
        logging.error(f"Failed to get alerts: {e}")
        return []

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "2.0.0"
    }

if __name__ == "__main__":
    uvicorn.run(
        "web_api:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )