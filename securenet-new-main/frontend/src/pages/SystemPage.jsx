import { useState, useEffect } from 'react'
import { 
  Play, 
  Square, 
  Wifi, 
  Activity, 
  Server,
  AlertTriangle,
  CheckCircle,
  RefreshCw,
  Network,
  Zap,
  HardDrive,
  Globe,
  Monitor,
  Gauge
} from 'lucide-react'
import { useSystemStore } from '../stores/systemStore'
import { useAuthStore } from '../stores/authStore'
import { StatusBadge } from '../components/StatusBadge'
import { LoadingSpinner, CardSkeleton } from '../components/LoadingSpinner'
import { api } from '../api/apiClient'
import toast from 'react-hot-toast'

function SystemStatusCard() {
  const { status, isLoading } = useSystemStore()

  if (isLoading || !status) {
    return <CardSkeleton />
  }

  return (
    <div className="card p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-medium text-gray-900 dark:text-white">
          System Status
        </h3>
        <StatusBadge 
          status={status.monitoring_active ? status.system_state : 'inactive'}
        />
      </div>
      
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-600 dark:text-gray-400">State</span>
          <span className="text-sm font-medium text-gray-900 dark:text-white">
            {status.system_state}
          </span>
        </div>
        
        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-600 dark:text-gray-400">Mode</span>
          <span className="text-sm font-medium text-gray-900 dark:text-white">
            {status.deployment_mode}
          </span>
        </div>
        
        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-600 dark:text-gray-400">Monitoring</span>
          <div className="flex items-center gap-2">
            {status.monitoring_active ? (
              <CheckCircle className="h-4 w-4 text-success-500" />
            ) : (
              <AlertTriangle className="h-4 w-4 text-danger-500" />
            )}
            <span className="text-sm font-medium text-gray-900 dark:text-white">
              {status.monitoring_active ? 'Active' : 'Inactive'}
            </span>
          </div>
        </div>
        
        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-600 dark:text-gray-400">Uptime</span>
          <span className="text-sm font-medium text-gray-900 dark:text-white">
            {status.uptime_formatted}
          </span>
        </div>
      </div>
    </div>
  )
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

function InterfaceHealthIndicator({ health }) {
  if (!health) return null
  
  const isHealthy = health.is_healthy
  const issueCount = health.issues?.length || 0
  
  return (
    <div className={`flex items-center gap-2 px-2 py-1 rounded-full text-xs font-medium ${
      isHealthy 
        ? 'bg-success-100 text-success-800 dark:bg-success-900 dark:text-success-200'
        : 'bg-danger-100 text-danger-800 dark:bg-danger-900 dark:text-danger-200'
    }`}>
      {isHealthy ? (
        <CheckCircle className="h-3 w-3" />
      ) : (
        <AlertTriangle className="h-3 w-3" />
      )}
      {isHealthy ? 'Healthy' : `${issueCount} Issues`}
    </div>
  )
}

function EnhancedNetworkInterfaceCard() {
  const { interfaces, fetchInterfaces, startMonitoring, stopMonitoring, status, isLoading } = useSystemStore()
  const { isAdmin } = useAuthStore()
  const [selectedInterface, setSelectedInterface] = useState('')
  const [isStarting, setIsStarting] = useState(false)
  const [isStopping, setIsStopping] = useState(false)
  const [interfaceHealth, setInterfaceHealth] = useState({})
  const [refreshing, setRefreshing] = useState(false)

  useEffect(() => {
    fetchInterfaces()
    refreshInterfaceData()
  }, [fetchInterfaces])

  const refreshInterfaceData = async () => {
    setRefreshing(true)
    try {
      await fetchInterfaces()
      // Fetch health data for each interface
      const healthData = {}
      for (const iface of interfaces) {
        try {
          const response = await api.network.getInterfaceHealth(iface.name)
          healthData[iface.name] = response.data
        } catch (error) {
          console.warn(`Failed to get health for ${iface.name}:`, error)
        }
      }
      setInterfaceHealth(healthData)
    } finally {
      setRefreshing(false)
    }
  }

  const handleStartMonitoring = async (interfaceName) => {
    setIsStarting(true)
    try {
      const result = await startMonitoring(interfaceName)
      if (result.success) {
        toast.success(`Monitoring started on ${interfaceName}`)
      }
    } finally {
      setIsStarting(false)
    }
  }

  const handleStopMonitoring = async () => {
    setIsStopping(true)
    try {
      await stopMonitoring()
    } finally {
      setIsStopping(false)
    }
  }

  const getInterfaceStatusColor = (iface) => {
    switch (iface.status) {
      case 'active': return 'text-success-600'
      case 'up': return 'text-warning-600'
      case 'down': return 'text-danger-600'
      default: return 'text-gray-600'
    }
  }

  const getInterfaceStatusIcon = (iface) => {
    switch (iface.status) {
      case 'active': return CheckCircle
      case 'up': return Activity
      case 'down': return AlertTriangle
      default: return Network
    }
  }

  return (
    <div className="card p-6">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <Network className="h-6 w-6 text-primary-600" />
          <div>
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">
              Network Interfaces
            </h3>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Auto-detected network interfaces with health monitoring
            </p>
          </div>
        </div>
        <button
          onClick={refreshInterfaceData}
          disabled={refreshing}
          className="btn btn-secondary btn-sm inline-flex items-center gap-2"
        >
          <RefreshCw className={`h-4 w-4 ${refreshing ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {isLoading ? (
        <div className="space-y-4">
          {[1, 2, 3].map(i => <CardSkeleton key={i} />)}
        </div>
      ) : interfaces.length === 0 ? (
        <div className="text-center py-8">
          <Network className="mx-auto h-12 w-12 text-gray-400 mb-4" />
          <p className="text-gray-600 dark:text-gray-400">No network interfaces detected</p>
        </div>
      ) : (
        <div className="space-y-4">
          {interfaces.map((iface) => {
            const StatusIcon = getInterfaceStatusIcon(iface)
            const health = interfaceHealth[iface.name]
            
            return (
              <div key={iface.name} className="border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <StatusIcon className={`h-5 w-5 ${getInterfaceStatusColor(iface)}`} />
                    <div>
                      <h4 className="font-medium text-gray-900 dark:text-white">
                        {iface.name}
                      </h4>
                      <div className="flex items-center gap-2 mt-1">
                        <StatusBadge status={iface.status} />
                        <InterfaceHealthIndicator health={health} />
                      </div>
                    </div>
                  </div>
                  
                  {isAdmin && (
                    <div className="flex items-center gap-2">
                      {status?.monitoring_active ? (
                        <button
                          onClick={handleStopMonitoring}
                          disabled={isStopping}
                          className="btn btn-danger btn-sm inline-flex items-center gap-2"
                        >
                          {isStopping ? (
                            <LoadingSpinner size="sm" />
                          ) : (
                            <Square className="h-3 w-3" />
                          )}
                          Stop
                        </button>
                      ) : (
                        <button
                          onClick={() => handleStartMonitoring(iface.name)}
                          disabled={isStarting || iface.status === 'down'}
                          className="btn btn-success btn-sm inline-flex items-center gap-2"
                        >
                          {isStarting ? (
                            <LoadingSpinner size="sm" />
                          ) : (
                            <Play className="h-3 w-3" />
                          )}
                          Monitor
                        </button>
                      )}
                    </div>
                  )}
                </div>
                
                {/* Interface Details */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                  <div>
                    <span className="text-gray-500 dark:text-gray-400">IP Address</span>
                    <div className="font-medium text-gray-900 dark:text-white">
                      {iface.ip_address || 'Not assigned'}
                    </div>
                  </div>
                  
                  <div>
                    <span className="text-gray-500 dark:text-gray-400">MAC Address</span>
                    <div className="font-medium text-gray-900 dark:text-white font-mono text-xs">
                      {iface.mac_address || 'Unknown'}
                    </div>
                  </div>
                  
                  <div>
                    <span className="text-gray-500 dark:text-gray-400">Speed</span>
                    <div className="font-medium text-gray-900 dark:text-white">
                      {iface.speed > 0 ? `${iface.speed} Mbps` : 'Unknown'}
                    </div>
                  </div>
                  
                  <div>
                    <span className="text-gray-500 dark:text-gray-400">MTU</span>
                    <div className="font-medium text-gray-900 dark:text-white">
                      {iface.mtu > 0 ? iface.mtu : 'Unknown'}
                    </div>
                  </div>
                </div>
                
                {/* Traffic Stats */}
                {(iface.bytes_sent > 0 || iface.bytes_recv > 0) && (
                  <div className="mt-3 pt-3 border-t border-gray-200 dark:border-gray-700">
                    <div className="flex items-center justify-between text-sm">
                      <div className="flex items-center gap-4">
                        <div className="flex items-center gap-1">
                          <div className="w-2 h-2 bg-success-500 rounded-full"></div>
                          <span className="text-gray-600 dark:text-gray-400">Sent:</span>
                          <span className="font-medium text-gray-900 dark:text-white">
                            {formatBytes(iface.bytes_sent)}
                          </span>
                        </div>
                        <div className="flex items-center gap-1">
                          <div className="w-2 h-2 bg-primary-500 rounded-full"></div>
                          <span className="text-gray-600 dark:text-gray-400">Received:</span>
                          <span className="font-medium text-gray-900 dark:text-white">
                            {formatBytes(iface.bytes_recv)}
                          </span>
                        </div>
                      </div>
                      {iface.duplex !== 'unknown' && (
                        <span className="text-gray-500 dark:text-gray-400 capitalize">
                          {iface.duplex}
                        </span>
                      )}
                    </div>
                  </div>
                )}
                
                {/* Health Issues */}
                {health?.issues && health.issues.length > 0 && (
                  <div className="mt-3 pt-3 border-t border-gray-200 dark:border-gray-700">
                    <div className="text-sm">
                      <span className="text-danger-600 dark:text-danger-400 font-medium">Issues:</span>
                      <ul className="mt-1 space-y-1">
                        {health.issues.map((issue, index) => (
                          <li key={index} className="text-gray-600 dark:text-gray-400 flex items-center gap-2">
                            <AlertTriangle className="h-3 w-3 text-danger-500" />
                            {issue}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
      
      {!isAdmin && (
        <div className="mt-6 text-center py-4 bg-warning-50 dark:bg-warning-900/20 rounded-lg">
          <AlertTriangle className="mx-auto h-6 w-6 text-warning-500 mb-2" />
          <p className="text-sm text-warning-800 dark:text-warning-200">
            Admin privileges required to control network monitoring
          </p>
        </div>
      )}
    </div>
  )
}

function SystemMetricsCard() {
  const { metrics, isLoading } = useSystemStore()

  if (isLoading || !metrics) {
    return <CardSkeleton />
  }

  const metricsData = [
    {
      label: 'Threats Detected',
      value: metrics.total_threats_detected || 0,
      icon: AlertTriangle,
      color: 'text-danger-600',
    },
    {
      label: 'Successful Mitigations',
      value: metrics.successful_mitigations || 0,
      icon: CheckCircle,
      color: 'text-success-600',
    },
    {
      label: 'Detection Accuracy',
      value: `${(metrics.detection_accuracy || 0).toFixed(1)}%`,
      icon: Activity,
      color: 'text-primary-600',
    },
    {
      label: 'Response Time',
      value: `${(metrics.average_response_time_ms || 0).toFixed(0)}ms`,
      icon: Server,
      color: 'text-primary-600',
    },
  ]

  return (
    <div className="card p-6">
      <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
        Performance Metrics
      </h3>
      
      <div className="grid grid-cols-2 gap-4">
        {metricsData.map((metric) => (
          <div key={metric.label} className="text-center">
            <metric.icon className={`h-8 w-8 mx-auto mb-2 ${metric.color}`} />
            <div className="text-2xl font-bold text-gray-900 dark:text-white">
              {metric.value}
            </div>
            <div className="text-sm text-gray-600 dark:text-gray-400">
              {metric.label}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

export default function SystemPage() {
  const { fetchStatus, fetchMetrics, startAutoRefresh, error } = useSystemStore()

  useEffect(() => {
    // Initial data fetch
    fetchStatus()
    fetchMetrics()

    // Start auto-refresh
    const stopAutoRefresh = startAutoRefresh()

    return () => {
      stopAutoRefresh()
    }
  }, [fetchStatus, fetchMetrics, startAutoRefresh])

  const handleRefresh = () => {
    fetchStatus()
    fetchMetrics()
  }

  if (error) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="mx-auto h-12 w-12 text-danger-500 mb-4" />
        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
          Failed to load system information
        </h3>
        <p className="text-gray-600 dark:text-gray-400 mb-4">{error}</p>
        <button
          onClick={handleRefresh}
          className="btn btn-primary btn-md"
        >
          Retry
        </button>
      </div>
    )
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Page header */}
      <div className="sm:flex sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold leading-7 text-gray-900 dark:text-white sm:truncate sm:text-3xl sm:tracking-tight">
            System Status
          </h1>
          <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
            Monitor and control the LAN Security System
          </p>
        </div>
        <div className="mt-4 sm:ml-16 sm:mt-0 sm:flex-none">
          <button
            onClick={handleRefresh}
            className="btn btn-primary btn-md inline-flex items-center gap-2"
          >
            <RefreshCw className="h-4 w-4" />
            Refresh
          </button>
        </div>
      </div>

      {/* System cards */}
      <div className="grid grid-cols-1 gap-6">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <SystemStatusCard />
          <SystemMetricsCard />
        </div>
        <EnhancedNetworkInterfaceCard />
      </div>
    </div>
  )
}