import { useState, useEffect } from 'react'
import { 
  Save, 
  RefreshCw,
  Settings as SettingsIcon,
  AlertTriangle,
  User,
  Shield,
  Bell,
  Monitor
} from 'lucide-react'
import { useForm } from 'react-hook-form'
import { api } from '../api/apiClient'
import { useAuthStore } from '../stores/authStore'
import { LoadingSpinner } from '../components/LoadingSpinner'
import toast from 'react-hot-toast'

function UserProfile() {
  const { user } = useAuthStore()

  return (
    <div className="card p-6">
      <div className="flex items-center mb-4">
        <User className="h-5 w-5 text-primary-600 mr-2" />
        <h3 className="text-lg font-medium text-gray-900 dark:text-white">
          User Profile
        </h3>
      </div>
      
      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            Username
          </label>
          <div className="mt-1 text-sm text-gray-900 dark:text-white">
            {user?.username}
          </div>
        </div>
        
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            Email
          </label>
          <div className="mt-1 text-sm text-gray-900 dark:text-white">
            {user?.email}
          </div>
        </div>
        
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            Role
          </label>
          <div className="mt-1">
            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
              user?.role === 'admin' 
                ? 'bg-primary-100 text-primary-800 dark:bg-primary-900 dark:text-primary-200'
                : 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200'
            }`}>
              {user?.role}
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}

function SystemConfiguration() {
  const [config, setConfig] = useState(null)
  const [isLoading, setIsLoading] = useState(true)
  const [isSaving, setIsSaving] = useState(false)
  const [error, setError] = useState(null)
  const { isAdmin } = useAuthStore()

  const { register, handleSubmit, reset, formState: { isDirty } } = useForm()

  const fetchConfig = async () => {
    try {
      setIsLoading(true)
      const response = await api.config.get()
      setConfig(response.data.configuration)
      reset(response.data.configuration)
      setError(null)
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to fetch configuration')
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    if (isAdmin) {
      fetchConfig()
    }
  }, [isAdmin])

  const onSubmit = async (data) => {
    try {
      setIsSaving(true)
      
      // Convert flat form data to nested structure for API
      const updates = []
      Object.entries(data).forEach(([key, value]) => {
        updates.push({ key, value })
      })
      
      await api.config.update(updates)
      toast.success('Configuration updated successfully')
      fetchConfig() // Refresh to get latest values
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Failed to update configuration')
    } finally {
      setIsSaving(false)
    }
  }

  if (!isAdmin) {
    return (
      <div className="card p-6">
        <div className="text-center py-8">
          <Shield className="mx-auto h-8 w-8 text-warning-500 mb-2" />
          <p className="text-sm text-gray-600 dark:text-gray-400">
            Admin privileges required to modify system configuration
          </p>
        </div>
      </div>
    )
  }

  if (isLoading) {
    return (
      <div className="card p-6">
        <div className="flex items-center justify-center py-8">
          <LoadingSpinner size="lg" />
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="card p-6">
        <div className="text-center py-8">
          <AlertTriangle className="mx-auto h-8 w-8 text-danger-500 mb-2" />
          <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">{error}</p>
          <button
            onClick={fetchConfig}
            className="btn btn-primary btn-sm"
          >
            Retry
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="card p-6">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center">
          <SettingsIcon className="h-5 w-5 text-primary-600 mr-2" />
          <h3 className="text-lg font-medium text-gray-900 dark:text-white">
            System Configuration
          </h3>
        </div>
        <button
          onClick={fetchConfig}
          disabled={isLoading}
          className="btn btn-secondary btn-sm inline-flex items-center gap-2"
        >
          <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
        {/* Detection Settings */}
        <div>
          <h4 className="text-md font-medium text-gray-900 dark:text-white mb-4">
            Detection Settings
          </h4>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                ARP Rate Threshold
              </label>
              <input
                type="number"
                {...register('detection.arp_rate_threshold')}
                className="input"
                min="1"
                max="100"
              />
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                ARP requests per second threshold
              </p>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                MAC Learning Threshold
              </label>
              <input
                type="number"
                {...register('detection.mac_learning_threshold')}
                className="input"
                min="10"
                max="1000"
              />
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                MAC addresses per port threshold
              </p>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Detection Window Size
              </label>
              <input
                type="number"
                {...register('detection.detection_window_size')}
                className="input"
                min="30"
                max="600"
              />
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                Analysis window in seconds
              </p>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                False Positive Threshold
              </label>
              <input
                type="number"
                step="0.01"
                {...register('detection.false_positive_threshold')}
                className="input"
                min="0.01"
                max="0.1"
              />
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                Maximum false positive rate (0.01 = 1%)
              </p>
            </div>
          </div>
        </div>

        {/* Performance Settings */}
        <div>
          <h4 className="text-md font-medium text-gray-900 dark:text-white mb-4">
            Performance Settings
          </h4>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Max Monitored Hosts
              </label>
              <input
                type="number"
                {...register('performance.max_monitored_hosts')}
                className="input"
                min="10"
                max="10000"
              />
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                Maximum number of hosts to monitor
              </p>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                CPU Utilization Threshold
              </label>
              <input
                type="number"
                step="0.1"
                {...register('performance.cpu_utilization_threshold')}
                className="input"
                min="0.1"
                max="1.0"
              />
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                CPU threshold (0.7 = 70%)
              </p>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Mitigation Response Time (ms)
              </label>
              <input
                type="number"
                {...register('performance.mitigation_response_time')}
                className="input"
                min="50"
                max="5000"
              />
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                Target response time in milliseconds
              </p>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Recovery Time Limit (s)
              </label>
              <input
                type="number"
                {...register('performance.recovery_time_limit')}
                className="input"
                min="5"
                max="300"
              />
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                Maximum recovery time in seconds
              </p>
            </div>
          </div>
        </div>

        {/* Logging Settings */}
        <div>
          <h4 className="text-md font-medium text-gray-900 dark:text-white mb-4">
            Logging Settings
          </h4>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Log Level
              </label>
              <select
                {...register('logging.log_level')}
                className="input"
              >
                <option value="DEBUG">Debug</option>
                <option value="INFO">Info</option>
                <option value="WARNING">Warning</option>
                <option value="ERROR">Error</option>
                <option value="CRITICAL">Critical</option>
              </select>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Max File Size (MB)
              </label>
              <input
                type="number"
                {...register('logging.max_file_size')}
                className="input"
                min="1"
                max="1000"
              />
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                Maximum log file size in MB
              </p>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Backup Count
              </label>
              <input
                type="number"
                {...register('logging.backup_count')}
                className="input"
                min="1"
                max="50"
              />
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                Number of backup log files to keep
              </p>
            </div>
          </div>
        </div>

        {/* Save button */}
        <div className="flex justify-end pt-6 border-t border-gray-200 dark:border-gray-700">
          <button
            type="submit"
            disabled={!isDirty || isSaving}
            className="btn btn-primary btn-md inline-flex items-center gap-2"
          >
            {isSaving ? (
              <LoadingSpinner size="sm" />
            ) : (
              <Save className="h-4 w-4" />
            )}
            Save Configuration
          </button>
        </div>
      </form>
    </div>
  )
}

export default function SettingsPage() {
  return (
    <div className="space-y-6 animate-fade-in">
      {/* Page header */}
      <div>
        <h1 className="text-2xl font-bold leading-7 text-gray-900 dark:text-white sm:truncate sm:text-3xl sm:tracking-tight">
          Settings
        </h1>
        <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
          Manage your profile and system configuration
        </p>
      </div>

      {/* Settings sections */}
      <div className="space-y-6">
        <UserProfile />
        <SystemConfiguration />
      </div>
    </div>
  )
}