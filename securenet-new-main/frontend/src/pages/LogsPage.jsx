import { useState, useEffect, useMemo } from 'react'
import { 
  Search, 
  RefreshCw,
  FileText,
  AlertTriangle,
  Download,
  Filter
} from 'lucide-react'
import { formatDistanceToNow, format } from 'date-fns'
import { api } from '../api/apiClient'
import { LoadingSpinner, TableSkeleton } from '../components/LoadingSpinner'
import { useDebounce } from '../hooks/useDebounce'

const logLevelColors = {
  DEBUG: 'text-gray-600 dark:text-gray-400',
  INFO: 'text-blue-600 dark:text-blue-400',
  WARNING: 'text-yellow-600 dark:text-yellow-400',
  ERROR: 'text-red-600 dark:text-red-400',
  CRITICAL: 'text-red-800 dark:text-red-300',
}

const eventTypeLabels = {
  security_event: 'Security Event',
  mitigation_action: 'Mitigation Action',
  recovery_confirmation: 'Recovery Confirmation',
  system_event: 'System Event',
}

function LogsTable({ logs, isLoading }) {
  if (isLoading) {
    return <TableSkeleton rows={15} columns={5} />
  }

  if (logs.length === 0) {
    return (
      <div className="text-center py-12">
        <FileText className="mx-auto h-12 w-12 text-gray-400 mb-4" />
        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
          No logs found
        </h3>
        <p className="text-gray-600 dark:text-gray-400">
          No log entries match your current filters.
        </p>
      </div>
    )
  }

  return (
    <div className="overflow-hidden shadow ring-1 ring-black ring-opacity-5 md:rounded-lg">
      <table className="min-w-full divide-y divide-gray-300 dark:divide-gray-700">
        <thead className="bg-gray-50 dark:bg-gray-800">
          <tr>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Timestamp
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Level
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Event Type
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Source
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Details
            </th>
          </tr>
        </thead>
        <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
          {logs.map((log, index) => (
            <tr key={index} className="hover:bg-gray-50 dark:hover:bg-gray-800">
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                <div>{format(new Date(log.timestamp), 'MMM d, HH:mm:ss')}</div>
                <div className="text-xs">
                  {formatDistanceToNow(new Date(log.timestamp), { addSuffix: true })}
                </div>
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                <span className={`text-sm font-medium ${logLevelColors[log.log_level] || 'text-gray-600'}`}>
                  {log.log_level}
                </span>
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                {eventTypeLabels[log.event_type] || log.event_type}
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                {log.source_component}
              </td>
              <td className="px-6 py-4 text-sm text-gray-900 dark:text-white">
                <div className="max-w-xs truncate">
                  {log.event_data && typeof log.event_data === 'object' ? (
                    <details className="cursor-pointer">
                      <summary className="hover:text-primary-600">
                        {log.event_data.attack_type || 
                         log.event_data.mitigation_id || 
                         log.event_data.recovery_id || 
                         'View details'}
                      </summary>
                      <pre className="mt-2 text-xs bg-gray-100 dark:bg-gray-800 p-2 rounded overflow-auto max-h-32">
                        {JSON.stringify(log.event_data, null, 2)}
                      </pre>
                    </details>
                  ) : (
                    <span>{JSON.stringify(log.event_data)}</span>
                  )}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default function LogsPage() {
  const [logs, setLogs] = useState([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState(null)
  const [searchTerm, setSearchTerm] = useState('')
  const [levelFilter, setLevelFilter] = useState('all')
  const [typeFilter, setTypeFilter] = useState('all')

  const debouncedSearchTerm = useDebounce(searchTerm, 300)

  const filteredLogs = useMemo(() => {
    return logs.filter(log => {
      const matchesSearch = !debouncedSearchTerm || 
        log.source_component.toLowerCase().includes(debouncedSearchTerm.toLowerCase()) ||
        log.event_type.toLowerCase().includes(debouncedSearchTerm.toLowerCase()) ||
        JSON.stringify(log.event_data).toLowerCase().includes(debouncedSearchTerm.toLowerCase())
      
      const matchesLevel = levelFilter === 'all' || log.log_level === levelFilter
      const matchesType = typeFilter === 'all' || log.event_type === typeFilter
      
      return matchesSearch && matchesLevel && matchesType
    })
  }, [logs, debouncedSearchTerm, levelFilter, typeFilter])

  const fetchLogs = async () => {
    try {
      setIsLoading(true)
      const response = await api.logs.getSecurity({ limit: 100 })
      setLogs(response.data.logs || [])
      setError(null)
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to fetch logs')
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchLogs()
  }, [])

  const handleExport = () => {
    const csvContent = [
      ['Timestamp', 'Level', 'Event Type', 'Source Component', 'Event Data'],
      ...filteredLogs.map(log => [
        log.timestamp,
        log.log_level,
        log.event_type,
        log.source_component,
        JSON.stringify(log.event_data)
      ])
    ].map(row => row.join(',')).join('\n')

    const blob = new Blob([csvContent], { type: 'text/csv' })
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `security-logs-${format(new Date(), 'yyyy-MM-dd')}.csv`
    a.click()
    window.URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Page header */}
      <div className="sm:flex sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold leading-7 text-gray-900 dark:text-white sm:truncate sm:text-3xl sm:tracking-tight">
            Security Logs
          </h1>
          <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
            View detailed system logs and audit trails
          </p>
        </div>
        <div className="mt-4 sm:ml-16 sm:mt-0 sm:flex-none">
          <button
            onClick={fetchLogs}
            disabled={isLoading}
            className="btn btn-primary btn-md inline-flex items-center gap-2"
          >
            <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="card p-6">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-4">
          {/* Search */}
          <div className="sm:col-span-2">
            <label htmlFor="search" className="sr-only">
              Search logs
            </label>
            <div className="relative">
              <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3">
                <Search className="h-5 w-5 text-gray-400" />
              </div>
              <input
                type="text"
                placeholder="Search logs..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="input pl-10"
              />
            </div>
          </div>

          {/* Level filter */}
          <div>
            <label htmlFor="level-filter" className="sr-only">
              Filter by level
            </label>
            <select
              value={levelFilter}
              onChange={(e) => setLevelFilter(e.target.value)}
              className="input"
            >
              <option value="all">All Levels</option>
              <option value="DEBUG">Debug</option>
              <option value="INFO">Info</option>
              <option value="WARNING">Warning</option>
              <option value="ERROR">Error</option>
              <option value="CRITICAL">Critical</option>
            </select>
          </div>

          {/* Type filter */}
          <div>
            <label htmlFor="type-filter" className="sr-only">
              Filter by type
            </label>
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="input"
            >
              <option value="all">All Types</option>
              <option value="security_event">Security Events</option>
              <option value="mitigation_action">Mitigation Actions</option>
              <option value="recovery_confirmation">Recovery Confirmations</option>
              <option value="system_event">System Events</option>
            </select>
          </div>
        </div>

        <div className="mt-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <span className="text-sm text-gray-600 dark:text-gray-400">
              {filteredLogs.length} of {logs.length} log entries
            </span>
          </div>
          <button
            onClick={handleExport}
            className="btn btn-secondary btn-sm inline-flex items-center gap-2"
          >
            <Download className="h-4 w-4" />
            Export CSV
          </button>
        </div>
      </div>

      {/* Logs table */}
      <div className="card overflow-hidden">
        {error ? (
          <div className="text-center py-12">
            <AlertTriangle className="mx-auto h-12 w-12 text-danger-500 mb-4" />
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
              Failed to load logs
            </h3>
            <p className="text-gray-600 dark:text-gray-400 mb-4">{error}</p>
            <button
              onClick={fetchLogs}
              className="btn btn-primary btn-md"
            >
              Retry
            </button>
          </div>
        ) : (
          <LogsTable logs={filteredLogs} isLoading={isLoading} />
        )}
      </div>
    </div>
  )
}