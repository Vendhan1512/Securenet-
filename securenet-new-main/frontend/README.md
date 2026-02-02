# LAN Security System - Frontend

A modern, production-ready React frontend for the LAN Security System. Built with performance, security, and user experience in mind.

## 🚀 Features

### Core Functionality
- **Real-time Dashboard** - Live security metrics and system status
- **Security Alerts Management** - View, filter, and export security alerts
- **Mitigation Actions** - Monitor automated response actions
- **System Control** - Start/stop monitoring with interface selection
- **Audit Logs** - Comprehensive security event logging
- **Configuration Management** - System settings and thresholds

### Technical Features
- **Authentication** - JWT-based auth with refresh tokens
- **Role-based Access** - Admin and operator roles
- **Real-time Updates** - Auto-refreshing data every 30 seconds
- **Responsive Design** - Mobile, tablet, and desktop optimized
- **Dark Mode** - System-wide theme switching
- **Performance Optimized** - Code splitting, lazy loading, memoization
- **Error Handling** - Comprehensive error boundaries and retry logic
- **Accessibility** - ARIA labels, keyboard navigation, screen reader support

## 🛠 Tech Stack

- **Framework**: React 18 with Vite
- **Styling**: Tailwind CSS
- **State Management**: Zustand
- **API Client**: Axios with interceptors
- **Routing**: React Router v6
- **Forms**: React Hook Form + Zod validation
- **Charts**: Recharts
- **Icons**: Lucide React
- **Animations**: Framer Motion
- **Notifications**: React Hot Toast

## 📦 Installation

### Prerequisites
- Node.js 18+ and npm/yarn
- LAN Security System backend running on `http://localhost:8000`

### Setup Steps

1. **Install Dependencies**
   ```bash
   cd frontend
   npm install
   ```

2. **Environment Configuration**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` if needed:
   ```env
   VITE_API_BASE_URL=http://localhost:8000
   VITE_WS_URL=ws://localhost:8000
   VITE_NODE_ENV=development
   VITE_APP_NAME=LAN Security System
   VITE_APP_VERSION=2.0.0
   ```

3. **Start Development Server**
   ```bash
   npm run dev
   ```
   
   The frontend will be available at `http://localhost:3000`

4. **Build for Production**
   ```bash
   npm run build
   ```

## 🔐 Authentication

### Demo Credentials
- **Admin**: `admin` / `admin123`
- **Operator**: `operator` / `operator123`

### Security Features
- JWT access tokens (memory-stored)
- Refresh tokens (localStorage)
- Automatic token refresh
- Secure logout on token expiry
- Role-based route protection

## 🎯 Usage

### Dashboard
- View real-time system status and metrics
- Monitor security trends with interactive charts
- See recent security alerts
- Quick system health overview

### Security Alerts
- Browse all detected security threats
- Filter by type, status, IP addresses
- Export alerts to CSV
- Real-time alert updates

### Mitigations
- Review automated response actions
- Track mitigation success rates
- View detailed action logs
- Export mitigation data

### System Control
- Start/stop network monitoring
- Select network interfaces
- View system performance metrics
- Monitor system uptime

### Logs & Audit
- Browse structured security logs
- Filter by level, type, component
- Search log content
- Export audit trails

### Settings
- View user profile information
- Configure system parameters (Admin only)
- Adjust detection thresholds
- Modify performance settings

## 🏗 Architecture

### Project Structure
```
src/
├── api/              # API client and endpoints
├── components/       # Reusable UI components
├── pages/           # Page components
├── layouts/         # Layout components
├── hooks/           # Custom React hooks
├── stores/          # Zustand state stores
├── utils/           # Utility functions
└── assets/          # Static assets
```

### State Management
- **Auth Store**: User authentication and authorization
- **System Store**: System status, metrics, and control
- **Theme Store**: Dark/light mode preference

### API Integration
- Centralized API client with interceptors
- Automatic token refresh
- Request/response error handling
- Loading states and retry logic

### Performance Optimizations
- **Code Splitting**: Lazy-loaded pages and components
- **Memoization**: React.memo, useMemo, useCallback
- **Debouncing**: Search inputs and API calls
- **Caching**: API response caching
- **Bundle Optimization**: Vendor chunks, tree shaking

## 🔧 Configuration

### Environment Variables
```env
# API Configuration
VITE_API_BASE_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000

# App Configuration
VITE_APP_NAME=LAN Security System
VITE_APP_VERSION=2.0.0
VITE_NODE_ENV=development
```

### Build Configuration
- **Vite**: Fast build tool with HMR
- **Tailwind**: Utility-first CSS framework
- **PostCSS**: CSS processing pipeline
- **ESLint**: Code linting and formatting

## 🚀 Deployment

### Production Build
```bash
npm run build
```

### Deployment Options

#### Static Hosting (Recommended)
```bash
# Build the app
npm run build

# Deploy the dist/ folder to:
# - Netlify
# - Vercel
# - AWS S3 + CloudFront
# - GitHub Pages
```

#### Docker Deployment
```dockerfile
FROM nginx:alpine
COPY dist/ /usr/share/nginx/html/
COPY nginx.conf /etc/nginx/nginx.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

#### Server Configuration
Ensure your web server serves `index.html` for all routes (SPA routing):

**Nginx**:
```nginx
location / {
  try_files $uri $uri/ /index.html;
}
```

**Apache**:
```apache
RewriteEngine On
RewriteRule ^(?!.*\.).*$ /index.html [L]
```

## 🧪 Testing

### Manual Testing Checklist
- [ ] Login/logout functionality
- [ ] Dashboard real-time updates
- [ ] Alert filtering and search
- [ ] System monitoring controls
- [ ] Dark mode switching
- [ ] Mobile responsiveness
- [ ] Error handling
- [ ] Performance (< 2s load time)

### Browser Support
- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## 🔍 Troubleshooting

### Common Issues

**API Connection Failed**
```bash
# Check backend is running
curl http://localhost:8000/health

# Verify CORS settings in backend
# Check VITE_API_BASE_URL in .env
```

**Build Errors**
```bash
# Clear node_modules and reinstall
rm -rf node_modules package-lock.json
npm install

# Clear Vite cache
rm -rf node_modules/.vite
```

**Authentication Issues**
```bash
# Clear browser storage
localStorage.clear()
sessionStorage.clear()

# Check JWT token expiry
# Verify backend auth endpoints
```

### Performance Issues
- Enable React DevTools Profiler
- Check Network tab for slow API calls
- Monitor bundle size with `npm run build`
- Use Lighthouse for performance auditing

## 📊 Monitoring

### Performance Metrics
- **First Contentful Paint**: < 1.5s
- **Largest Contentful Paint**: < 2.5s
- **Time to Interactive**: < 3.5s
- **Bundle Size**: < 500KB gzipped

### Error Monitoring
- Error boundaries catch React errors
- API errors logged to console
- User-friendly error messages
- Retry mechanisms for failed requests

## 🤝 Contributing

### Development Workflow
1. Create feature branch
2. Implement changes with tests
3. Run linting: `npm run lint`
4. Build and test: `npm run build`
5. Submit pull request

### Code Standards
- Use TypeScript for new components
- Follow React best practices
- Implement proper error handling
- Add loading states for async operations
- Ensure accessibility compliance

## 📄 License

This project is part of the LAN Security System and follows the same licensing terms.

---

## 🎉 Ready for Production!

This frontend is production-ready with:
- ✅ **Security**: JWT auth, XSS protection, secure API calls
- ✅ **Performance**: Code splitting, lazy loading, optimized bundles
- ✅ **Reliability**: Error boundaries, retry logic, graceful degradation
- ✅ **Accessibility**: ARIA labels, keyboard navigation, screen readers
- ✅ **Responsiveness**: Mobile-first design, cross-browser compatibility
- ✅ **Maintainability**: Clean architecture, reusable components, TypeScript ready

**Deploy with confidence!** 🚀