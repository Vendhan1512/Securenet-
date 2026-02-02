# LAN Security System - Deployment Guide

## 🚀 Quick Start

### Prerequisites
- Python 3.8+ with pip
- Node.js 18+ with npm
- Network interface access for monitoring

### Backend Setup (FastAPI)

1. **Install Python Dependencies**
   ```bash
   pip install fastapi uvicorn python-jose[cryptography] passlib[bcrypt] python-multipart PyJWT
   ```

2. **Start Backend Server**
   ```bash
   python web_api.py
   ```
   - Server runs on: `http://localhost:8000`
   - API Documentation: `http://localhost:8000/docs`

### Frontend Setup (React)

1. **Install Dependencies**
   ```bash
   cd frontend
   npm install
   ```

2. **Configure Environment**
   ```bash
   cp .env.example .env
   # Edit .env if needed (default settings work for local development)
   ```

3. **Start Development Server**
   ```bash
   npm run dev
   ```
   - Frontend runs on: `http://localhost:5173`

## 🔐 Authentication

### Demo Credentials
- **Admin**: `admin` / `admin123`
- **Operator**: `operator` / `operator123`

### Features by Role
- **Admin**: Full system control, configuration, monitoring management
- **Operator**: View-only access to dashboards, alerts, and logs

## 🎯 System Features

### Real-time Dashboard
- Live security metrics and system status
- Interactive charts showing threat trends
- Recent security alerts overview
- System performance monitoring

### Security Management
- **Alerts**: Browse, filter, and export security alerts
- **Mitigations**: Track automated response actions
- **System Control**: Start/stop network monitoring
- **Audit Logs**: Comprehensive security event logging

### Network Monitoring
- ARP spoofing detection
- MAC flooding detection  
- DNS spoofing detection
- Automated threat mitigation
- Network recovery procedures

## 🏗 Production Deployment

### Backend (FastAPI)
```bash
# Using uvicorn directly
uvicorn web_api:app --host 0.0.0.0 --port 8000 --workers 4

# Or using the production script
python production_main.py --daemon --interface eth0
```

### Frontend (React)
```bash
# Build for production
cd frontend
npm run build

# Deploy the dist/ folder to:
# - Nginx/Apache web server
# - AWS S3 + CloudFront
# - Netlify/Vercel
# - Docker container
```

### Docker Deployment
```dockerfile
# Backend Dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "web_api:app", "--host", "0.0.0.0", "--port", "8000"]

# Frontend Dockerfile  
FROM nginx:alpine
COPY frontend/dist/ /usr/share/nginx/html/
EXPOSE 80
```

## 🔧 Configuration

### Environment Variables
```env
# Backend
VITE_API_BASE_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000
VITE_NODE_ENV=production

# Security (change in production)
SECRET_KEY=your-secret-key-change-in-production
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
```

### Network Interface Selection
- Use `python production_main.py --interactive` to see available interfaces
- Common interfaces: `eth0`, `wlan0`, `en0` (varies by system)
- Requires appropriate network permissions

## 📊 Monitoring & Maintenance

### Health Checks
- Backend: `GET /health`
- Frontend: Check if page loads correctly
- System: Monitor logs in `logs/` directory

### Log Files
- `production_security.log` - System operations
- `web_api.log` - API requests and responses
- `logs/security_events.jsonl` - Security events (JSON Lines format)

### Performance Metrics
- Response time: < 200ms target
- Detection accuracy: > 95% target
- System uptime: Monitored automatically
- Memory usage: Check system resources

## 🛡 Security Considerations

### Production Hardening
1. **Change Default Credentials**: Update admin/operator passwords
2. **Use HTTPS**: Configure SSL/TLS certificates
3. **Network Segmentation**: Deploy in secure network segment
4. **Access Control**: Implement firewall rules
5. **Regular Updates**: Keep dependencies updated
6. **Backup Strategy**: Regular configuration and log backups

### Network Permissions
- Requires raw socket access for packet capture
- May need to run with elevated privileges
- Consider using capabilities instead of root access

## 🔍 Troubleshooting

### Common Issues

**Backend won't start**
```bash
# Check Python version
python --version

# Install missing dependencies
pip install -r requirements.txt

# Check port availability
netstat -an | grep 8000
```

**Frontend build errors**
```bash
# Clear cache and reinstall
rm -rf node_modules package-lock.json
npm install

# Check Node.js version
node --version
```

**Authentication failures**
- Verify credentials in `fake_users_db` (web_api.py)
- Check JWT token expiration
- Clear browser localStorage

**Network monitoring issues**
- Verify interface name: `ip addr show` (Linux) or `ipconfig` (Windows)
- Check network permissions
- Ensure interface is active and has traffic

### Support
- Check logs in `logs/` directory
- Run `python test_system.py` to verify API functionality
- Monitor system resources (CPU, memory, network)

## 🎉 Success!

Your LAN Security System is now deployed and ready to protect your network from:
- ✅ ARP spoofing attacks
- ✅ MAC flooding attacks  
- ✅ DNS spoofing attacks
- ✅ Other network-based threats

The system provides real-time monitoring, automated threat response, and comprehensive security logging for enterprise network protection.