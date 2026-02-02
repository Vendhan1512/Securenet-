import { create } from 'zustand'
import { api } from '../api/apiClient'
import toast from 'react-hot-toast'

export const useSystemStore = create((set, get) => ({
  status: null,
  metrics: null,
  interfaces: [],
  isLoading: false,
  error: null,
  lastUpdated: null,

  // Fetch system status
  fetchStatus: async () => {
    try {
      set({ isLoading: true, error: null })
      const response = await api.system.getStatus()
      set({
        status: response.data,
        isLoading: false,
        lastUpdated: new Date(),
      })
    } catch (error) {
      set({
        error: error.response?.data?.detail || 'Failed to fetch system status',
        isLoading: false,
      })
    }
  },

  // Fetch security metrics
  fetchMetrics: async () => {
    try {
      const response = await api.system.getMetrics()
      set({
        metrics: response.data,
        lastUpdated: new Date(),
      })
    } catch (error) {
      set({
        error: error.response?.data?.detail || 'Failed to fetch metrics',
      })
    }
  },

  // Fetch network interfaces
  fetchInterfaces: async () => {
    try {
      const response = await api.network.getInterfaces()
      set({
        interfaces: response.data.interfaces || [],
      })
    } catch (error) {
      set({
        error: error.response?.data?.detail || 'Failed to fetch interfaces',
      })
    }
  },

  // Start monitoring
  startMonitoring: async (interfaceName) => {
    try {
      set({ isLoading: true, error: null })
      await api.system.startMonitoring(interfaceName)
      
      // Refresh status after starting
      await get().fetchStatus()
      
      toast.success(`Monitoring started on ${interfaceName}`)
      return { success: true }
    } catch (error) {
      const errorMessage = error.response?.data?.detail || 'Failed to start monitoring'
      set({
        error: errorMessage,
        isLoading: false,
      })
      toast.error(errorMessage)
      return { success: false, error: errorMessage }
    }
  },

  // Stop monitoring
  stopMonitoring: async () => {
    try {
      set({ isLoading: true, error: null })
      await api.system.stopMonitoring()
      
      // Refresh status after stopping
      await get().fetchStatus()
      
      toast.success('Monitoring stopped')
      return { success: true }
    } catch (error) {
      const errorMessage = error.response?.data?.detail || 'Failed to stop monitoring'
      set({
        error: errorMessage,
        isLoading: false,
      })
      toast.error(errorMessage)
      return { success: false, error: errorMessage }
    }
  },

  // Auto-refresh data
  startAutoRefresh: () => {
    const interval = setInterval(() => {
      get().fetchStatus()
      get().fetchMetrics()
    }, 30000) // Refresh every 30 seconds

    return () => clearInterval(interval)
  },

  // Clear error
  clearError: () => set({ error: null }),
}))