import axios from 'axios'
import toast from 'react-hot-toast'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

// Create axios instance
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Token management
let accessToken = null
let refreshToken = null

export const setTokens = (tokens) => {
  accessToken = tokens.access_token
  refreshToken = tokens.refresh_token
  
  // Store refresh token in localStorage (access token stays in memory)
  if (refreshToken) {
    localStorage.setItem('refresh_token', refreshToken)
  }
}

export const clearTokens = () => {
  accessToken = null
  refreshToken = null
  localStorage.removeItem('refresh_token')
}

export const getStoredRefreshToken = () => {
  return localStorage.getItem('refresh_token')
}

// Request interceptor to add auth token
apiClient.interceptors.request.use(
  (config) => {
    if (accessToken) {
      config.headers.Authorization = `Bearer ${accessToken}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor for token refresh and error handling
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config

    // Handle 401 errors (token expired)
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true

      try {
        const storedRefreshToken = getStoredRefreshToken()
        if (storedRefreshToken) {
          const response = await axios.post(`${API_BASE_URL}/api/auth/refresh`, {
            refresh_token: storedRefreshToken,
          })

          const tokens = response.data
          setTokens(tokens)

          // Retry original request with new token
          originalRequest.headers.Authorization = `Bearer ${tokens.access_token}`
          return apiClient(originalRequest)
        }
      } catch (refreshError) {
        // Refresh failed, redirect to login
        clearTokens()
        window.location.href = '/auth/login'
        return Promise.reject(refreshError)
      }
    }

    // Handle other errors
    if (error.response?.status >= 500) {
      toast.error('Server error. Please try again later.')
    } else if (error.response?.status === 403) {
      toast.error('Access denied. Insufficient permissions.')
    } else if (error.response?.status === 404) {
      toast.error('Resource not found.')
    } else if (error.code === 'ECONNABORTED') {
      toast.error('Request timeout. Please check your connection.')
    } else if (!error.response) {
      toast.error('Network error. Please check your connection.')
    }

    return Promise.reject(error)
  }
)

// API methods
export const api = {
  // Authentication
  auth: {
    login: (credentials) => apiClient.post('/api/auth/login', credentials),
    refresh: (refreshToken) => apiClient.post('/api/auth/refresh', { refresh_token: refreshToken }),
    me: () => apiClient.get('/api/auth/me'),
  },

  // System
  system: {
    getStatus: () => apiClient.get('/api/system/status'),
    getMetrics: () => apiClient.get('/api/system/metrics'),
    startMonitoring: (interfaceName) => apiClient.post('/api/system/start-monitoring', { interface: interfaceName }),
    stopMonitoring: () => apiClient.post('/api/system/stop-monitoring'),
  },

  // Security
  security: {
    getAlerts: (params = {}) => apiClient.get('/api/security/alerts', { params }),
    getMitigations: (params = {}) => apiClient.get('/api/security/mitigations', { params }),
  },

  // Network
  network: {
    getInterfaces: () => apiClient.get('/api/network/interfaces'),
    getInterfaceHealth: (interfaceName) => apiClient.get(`/api/network/interfaces/${encodeURIComponent(interfaceName)}/health`),
  },

  // Logs
  logs: {
    getSecurity: (params = {}) => apiClient.get('/api/logs/security', { params }),
  },

  // Configuration
  config: {
    get: () => apiClient.get('/api/config'),
    update: (updates) => apiClient.put('/api/config', updates),
  },

  // Health
  health: () => apiClient.get('/health'),
}

export default apiClient