import { useState, useEffect } from 'react'
import { formatDistanceToNow } from 'date-fns'
import { AlertTriangle, Shield, Wifi } from 'lucide-react'
import { api } from '../api/apiClient'
import { StatusBadge } from './StatusBadge'
import { LoadingSpinner } from './LoadingSpinner'

const attackTypeIcons = {
  arp_spoofing: Shield,
  mac_flooding: Wifi,
  dns_spoofing: AlertTriangle,
}

const attackTypeLabels = {
  arp_spoofing: 'ARP Spoofing',
  mac_flooding: 'MAC Flooding',
  dns_spoofing: 'DNS Spoofing',
}

export function RecentAlerts() {
  const [alerts, setAlerts] = useState([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    const fetchAlerts = async () => {
      try {
        setIsLoading(true)
        const response = await api.security.getAlerts({ limit: 5 })
        setAlerts(response.data.alerts || [])
        setError(null)
      } catch (err) {
        setError(err.response?.data?.detail || 'Failed to fetch alerts')
      } finally {
        setIsLoading(false)
      }
    }

    fetchAlerts()

    // Refresh alerts every 30 seconds
    const interval = setInterval(fetchAlerts, 30000)
    return () => clearInterval(interval)
  }, [])

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-32">
        <LoadingSpinner size="md" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="text-center py-8">
        <AlertTriangle className="mx-auto h-8 w-8 text-danger-500 mb-2" />
        <p className="text-sm text-gray-600 dark:text-gray-400">{error}</p>
      </div>
    )
  }

  if (alerts.length === 0) {
    return (
      <div className="text-center py-8">
        <Shield className="mx-auto h-8 w-8 text-success-500 mb-2" />
        <p className="text-sm text-gray-600 dark:text-gray-400">
          No recent security alerts
        </p>
        <p className="text-xs text-gray-500 dark:text-gray-500 mt-1">
          Your network is secure
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {alerts.map((alert) => {
        const Icon = attackTypeIcons[alert.attack_type] || AlertTriangle
        const attackLabel = attackTypeLabels[alert.attack_type] || alert.attack_type
        
        return (
          <div
            key={alert.id}
            className="flex items-start space-x-3 p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
          >
            <div className="flex-shrink-0">
              <Icon className="h-5 w-5 text-danger-500" />
            </div>
            
            <div className="flex-1 min-w-0">
              <div className="flex items-center justify-between">
                <p className="text-sm font-medium text-gray-900 dark:text-white">
                  {attackLabel}
                </p>
                <StatusBadge status={alert.status} />
              </div>
              
              <div className="mt-1 text-xs text-gray-600 dark:text-gray-400 space-y-1">
                <div>Source: {alert.source_ip} ({alert.source_mac})</div>
                <div>Target: {alert.target_ip}</div>
                <div className="flex items-center justify-between">
                  <span>Confidence: {(alert.confidence_score * 100).toFixed(0)}%</span>
                  <span>
                    {formatDistanceToNow(new Date(alert.timestamp), { addSuffix: true })}
                  </span>
                </div>
              </div>
            </div>
          </div>
        )
      })}
      
      <div className="pt-2 border-t border-gray-200 dark:border-gray-600">
        <button className="text-sm text-primary-600 dark:text-primary-400 hover:text-primary-700 dark:hover:text-primary-300 font-medium">
          View all alerts →
        </button>
      </div>
    </div>
  )
}