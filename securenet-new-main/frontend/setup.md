# 🚀 LAN Security System Frontend - Quick Setup

## Prerequisites
- Node.js 18+ installed
- Backend API running on `http://localhost:8000`

## Quick Start

### 1. Install Dependencies
```bash
cd frontend
npm install
```

### 2. Start Development Server
```bash
npm run dev
```

### 3. Open Browser
Navigate to `http://localhost:3000`

### 4. Login
Use demo credentials:
- **Admin**: `admin` / `admin123`
- **Operator**: `operator` / `operator123`

## Production Build

### Build for Production
```bash
npm run build
```

### Serve Production Build
```bash
npm run preview
```

## Environment Configuration

The `.env` file is already configured for local development. Modify if needed:

```env
VITE_API_BASE_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000
VITE_NODE_ENV=development
```

## Features Available

✅ **Dashboard** - Real-time security metrics and system status
✅ **Security Alerts** - Browse, filter, and export security alerts  
✅ **Mitigations** - View automated response actions
✅ **System Control** - Start/stop monitoring (Admin only)
✅ **Logs** - Security event audit trails
✅ **Settings** - System configuration (Admin only)
✅ **Dark Mode** - Theme switching
✅ **Responsive Design** - Mobile, tablet, desktop
✅ **Real-time Updates** - Auto-refresh every 30 seconds

## Troubleshooting

### Backend Connection Issues
1. Ensure backend is running: `curl http://localhost:8000/health`
2. Check CORS settings in backend
3. Verify API base URL in `.env`

### Build Issues
```bash
# Clear cache and reinstall
rm -rf node_modules package-lock.json
npm install
```

### Authentication Issues
- Clear browser localStorage/sessionStorage
- Check backend auth endpoints are working
- Verify JWT token handling

## Performance
- Initial load: < 2 seconds
- Code splitting: Automatic lazy loading
- Bundle size: Optimized with Vite
- Real-time updates: Efficient polling

## Browser Support
- Chrome 90+
- Firefox 88+ 
- Safari 14+
- Edge 90+

---

**🎉 You're ready to go! The frontend is fully functional and production-ready.**