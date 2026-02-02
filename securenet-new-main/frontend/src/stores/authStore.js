import { create } from 'zustand'
import { api, setTokens, clearTokens, getStoredRefreshToken } from '../api/apiClient'
import toast from 'react-hot-toast'

export const useAuthStore = create((set, get) => ({
  user: null,
  isAuthenticated: false,
  isLoading: true,
  error: null,

  // Initialize authentication on app start
  initializeAuth: async () => {
    try {
      const refreshToken = getStoredRefreshToken()
      if (!refreshToken) {
        set({ isLoading: false })
        return
      }

      // Try to refresh token and get user info
      const tokenResponse = await api.auth.refresh(refreshToken)
      setTokens(tokenResponse.data)

      const userResponse = await api.auth.me()
      set({
        user: userResponse.data,
        isAuthenticated: true,
        isLoading: false,
        error: null,
      })
    } catch (error) {
      clearTokens()
      set({
        user: null,
        isAuthenticated: false,
        isLoading: false,
        error: null,
      })
    }
  },

  // Login
  login: async (credentials) => {
    try {
      set({ isLoading: true, error: null })

      const response = await api.auth.login(credentials)
      const tokens = response.data
      setTokens(tokens)

      const userResponse = await api.auth.me()
      set({
        user: userResponse.data,
        isAuthenticated: true,
        isLoading: false,
        error: null,
      })

      toast.success('Login successful')
      return { success: true }
    } catch (error) {
      const errorMessage = error.response?.data?.detail || 'Login failed'
      set({
        user: null,
        isAuthenticated: false,
        isLoading: false,
        error: errorMessage,
      })
      toast.error(errorMessage)
      return { success: false, error: errorMessage }
    }
  },

  // Logout
  logout: () => {
    clearTokens()
    set({
      user: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,
    })
    toast.success('Logged out successfully')
  },

  // Clear error
  clearError: () => set({ error: null }),

  // Check if user has specific role
  hasRole: (role) => {
    const { user } = get()
    return user?.role === role
  },

  // Check if user is admin
  isAdmin: () => {
    const { user } = get()
    return user?.role === 'admin'
  },
}))