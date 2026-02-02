import { useEffect, useMemo } from 'react'
import { 
  Shield, 
  AlertTriangle, 
  ShieldCheck, 
  Activity,
  TrendingUp,
  Clock,
  Zap
} from 'lucide-react'
import { useSystemStore } from '../stores/systemStore'
import { LoadingSpinner, CardSkeleton } from '../components/LoadingSpinner'
import { StatusBadge } from '../components/StatusBadge'
import { MetricsChart } from '../components/MetricsChart'
import { RecentAlerts } from '../components/RecentAlerts'

function MetricCard({ title, value, icon: Icon, status, subtitle, isLoading }) {
  if (isLoading) {
    return <CardSkeleton />
  }

  return (
    <div className="card p-6">
      <div className="flex items-center">
        <div className="flex-shrink-0">
          <Icon className="h-8 w-8 text-primary-600" />
        </div>
        <div className="ml-5 w-0 flex-1">
          <dl>
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">
              {title}
            </dt>
            <dd className="flex items-baseline">
              <div className="text-2xl font-semibold text-gray-900 dark:text-white">
                {value}
              </div>
              {status && (
                <div className="ml-2">
                  <StatusBadge status={status} />
                </div>
              )}
            </dd>
            {subtitle && (
              <dd className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                {subtitle}
              </dd>
            )}
          </dl>
        </div>
      </div>
    </div>
  )
}

function SystemOverview() {
  const { status, metrics, isLoading } = useSystemStore()

  const systemMetrics = useMemo(() => {
    if (!status || !metrics) return []

    return [
      {
        title: 'System Status',
        value: status.system_state,
        icon: Shield,
        status: status.monitoring_active ? status.system_state : 'inactive',
        subtitle: status.monitoring_active ? 'Monitoring Active' : 'Monitoring Inactive',
      },
      {
        title: 'Threats Detected',
        value: metrics.total_threats_detected || 0,
        icon: AlertTriangle,
        status: metrics.total_threats_detected > 0 ? 'warning' : 'success',
        subtitle: 'Total security events',
      },
      {
        title: 'Successful Mitigations',
        value: metrics.successful_mitigations || 0,
        icon: ShieldCheck,
        status: 'success',
        subtitle: `${metrics.mitigation_success_rate?.toFixed(1) || 0}% success rate`,
      },
      {
        title: 'System Uptime',
        value: status.uptime_formatted || '0:00:00',
        icon: Clock,
        status: 'info',
        subtitle: 'Current session',
      },
      {
        title: 'Detection Accuracy',
        value: `${metrics.detection_accuracy?.toFixed(1) || 0}%`,
        icon: TrendingUp,
        status: metrics.detection_accuracy >= 95 ? 'success' : 'warning',
        subtitle: 'Accuracy rate',
      },
      {
        title: 'Response Time',
        value: `${metrics.average_response_time_ms?.toFixed(0) || 0}ms`,
        icon: Zap,
        status: metrics.average_response_time_ms <= 200 ? 'success' : 'warning',
        subtitle: 'Average response',
      },
    ]
  }, [status, metrics])

  return (
    <div>
      <h2 className="text-lg font-medium text-gray-900 dark:text-white mb-6">
        System Overview
      </h2>
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-3">
        {systemMetrics.map((metric, index) => (
          <MetricCard
            key={metric.title}
            {...metric}
            isLoading={isLoading && index < 3}
          />
        ))}
      </div>
    </div>
  )
}

export default function DashboardPage() {
  const { 
    fetchStatus, 
    fetchMetrics, 
    startAutoRefresh,
    isLoading,
    error 
  } = useSystemStore()

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

  if (error) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="mx-auto h-12 w-12 text-danger-500 mb-4" />
        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
          Failed to load dashboard
        </h3>
        <p className="text-gray-600 dark:text-gray-400 mb-4">{error}</p>
        <button
          onClick={() => {
            fetchStatus()
            fetchMetrics()
          }}
          className="btn btn-primary btn-md"
        >
          Retry
        </button>
      </div>
    )
  }

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Page header */}
      <div>
        <h1 className="text-2xl font-bold leading-7 text-gray-900 dark:text-white sm:truncate sm:text-3xl sm:tracking-tight">
          Security Dashboard
        </h1>
        <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
          Real-time network security monitoring and threat detection overview
        </p>
      </div>

      {/* System Overview */}
      <SystemOverview />

      {/* Charts and Recent Activity */}
      <div className="grid grid-cols-1 gap-8 lg:grid-cols-2">
        {/* Metrics Chart */}
        <div className="card p-6">
          <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
            Security Metrics Trend
          </h3>
          {isLoading ? (
            <div className="h-64 flex items-center justify-center">
              <LoadingSpinner size="lg" />
            </div>
          ) : (
            <MetricsChart />
          )}
        </div>

        {/* Recent Alerts */}
        <div className="card p-6">
          <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
            Recent Security Alerts
          </h3>
          <RecentAlerts />
        </div>
      </div>
    </div>
  )
}