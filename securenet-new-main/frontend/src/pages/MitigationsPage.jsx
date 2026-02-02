import { useState, useEffect, useMemo } from 'react'
import { 
  Search, 
  RefreshCw,
  ShieldCheck,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Download
} from 'lucide-react'
import { formatDistanceToNow, format } from 'date-fns'
import { api } from '../api/apiClient'
import { StatusBadge } from '../components/StatusBadge'
import { LoadingSpinner, TableSkeleton } from '../components/LoadingSpinner'
import { useDebounce } from '../hooks/useDebounce'

function MitigationsTable({ mitigations, isLoading }) {
  if (isLoading) {
    return <TableSkeleton rows={10} columns={5} />
  }

  if (mitigations.length === 0) {
    return (
      <div className="text-center py-12">
        <ShieldCheck className="mx-auto h-12 w-12 text-gray-400 mb-4" />
        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
          No mitigations found
        </h3>
        <p className="text-gray-600 dark:text-gray-400">
          No mitigation actions match your current filters.
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
              Mitigation
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Attack Type
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Actions Taken
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Status
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Time
            </th>
          </tr>
        </thead>
        <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
          {mitigations.map((mitigation) => (
            <tr key={mitigation.id} className="hover:bg-gray-50 dark:hover:bg-gray-800">
              <td className="px-6 py-4 whitespace-nowrap">
                <div className="flex items-center">
                  {mitigation.success ? (
                    <CheckCircle className="h-5 w-5 text-success-500 mr-3" />
                  ) : (
                    <XCircle className="h-5 w-5 text-danger-500 mr-3" />
                  )}
                  <div>
                    <div className="text-sm font-medium text-gray-900 dark:text-white">
                      {mitigation.id}
                    </div>
                    <div className="text-sm text-gray-500 dark:text-gray-400">
                      Mitigation ID
                    </div>
                  </div>
                </div>
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                <div className="text-sm text-gray-900 dark:text-white">
                  {mitigation.attack_type.replace('_', ' ').toUpperCase()}
                </div>
              </td>
              <td className="px-6 py-4">
                <div className="text-sm text-gray-900 dark:text-white">
                  <ul className="list-disc list-inside space-y-1">
                    {mitigation.actions_taken.map((action, index) => (
                      <li key={index} className="truncate max-w-xs">
                        {action}
                      </li>
                    ))}
                  </ul>
                </div>
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                <StatusBadge status={mitigation.success ? 'success' : 'failed'}>
                  {mitigation.success ? 'Success' : 'Failed'}
                </StatusBadge>
                {mitigation.error_message && (
                  <div className="text-xs text-danger-600 dark:text-danger-400 mt-1">
                    {mitigation.error_message}
                  </div>
                )}
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                <div>{format(new Date(mitigation.timestamp), 'MMM d, HH:mm')}</div>
                <div className="text-xs">
                  {formatDistanceToNow(new Date(mitigation.timestamp), { addSuffix: true })}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default function MitigationsPage() {
  const [mitigations, setMitigations] = useState([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState(null)
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')

  const debouncedSearchTerm = useDebounce(searchTerm, 300)

  const filteredMitigations = useMemo(() => {
    return mitigations.filter(mitigation => {
      const matchesSearch = !debouncedSearchTerm || 
        mitigation.id.includes(debouncedSearchTerm) ||
        mitigation.attack_type.includes(debouncedSearchTerm) ||
        mitigation.actions_taken.some(action => 
          action.toLowerCase().includes(debouncedSearchTerm.toLowerCase())
        )
      
      const matchesStatus = statusFilter === 'all' || 
        (statusFilter === 'success' && mitigation.success) ||
        (statusFilter === 'failed' && !mitigation.success)
      
      return matchesSearch && matchesStatus
    })
  }, [mitigations, debouncedSearchTerm, statusFilter])

  const fetchMitigations = async () => {
    try {
      setIsLoading(true)
      const response = await api.security.getMitigations({ limit: 100 })
      setMitigations(response.data.mitigations || [])
      setError(null)
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to fetch mitigations')
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchMitigations()
  }, [])

  const handleExport = () => {
    const csvContent = [
      ['ID', 'Attack Type', 'Actions Taken', 'Success', 'Error Message', 'Timestamp'],
      ...filteredMitigations.map(mitigation => [
        mitigation.id,
        mitigation.attack_type,
        mitigation.actions_taken.join('; '),
        mitigation.success,
        mitigation.error_message || '',
        mitigation.timestamp
      ])
    ].map(row => row.join(',')).join('\n')

    const blob = new Blob([csvContent], { type: 'text/csv' })
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `mitigation-actions-${format(new Date(), 'yyyy-MM-dd')}.csv`
    a.click()
    window.URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Page header */}
      <div className="sm:flex sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold leading-7 text-gray-900 dark:text-white sm:truncate sm:text-3xl sm:tracking-tight">
            Mitigation Actions
          </h1>
          <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
            Review automated responses to security threats
          </p>
        </div>
        <div className="mt-4 sm:ml-16 sm:mt-0 sm:flex-none">
          <button
            onClick={fetchMitigations}
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
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          {/* Search */}
          <div className="sm:col-span-2">
            <label htmlFor="search" className="sr-only">
              Search mitigations
            </label>
            <div className="relative">
              <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3">
                <Search className="h-5 w-5 text-gray-400" />
              </div>
              <input
                type="text"
                placeholder="Search by ID, type, or actions..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="input pl-10"
              />
            </div>
          </div>

          {/* Status filter */}
          <div>
            <label htmlFor="status-filter" className="sr-only">
              Filter by status
            </label>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="input"
            >
              <option value="all">All Statuses</option>
              <option value="success">Successful</option>
              <option value="failed">Failed</option>
            </select>
          </div>
        </div>

        <div className="mt-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <span className="text-sm text-gray-600 dark:text-gray-400">
              {filteredMitigations.length} of {mitigations.length} mitigations
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

      {/* Mitigations table */}
      <div className="card overflow-hidden">
        {error ? (
          <div className="text-center py-12">
            <AlertTriangle className="mx-auto h-12 w-12 text-danger-500 mb-4" />
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
              Failed to load mitigations
            </h3>
            <p className="text-gray-600 dark:text-gray-400 mb-4">{error}</p>
            <button
              onClick={fetchMitigations}
              className="btn btn-primary btn-md"
            >
              Retry
            </button>
          </div>
        ) : (
          <MitigationsTable mitigations={filteredMitigations} isLoading={isLoading} />
        )}
      </div>
    </div>
  )
}