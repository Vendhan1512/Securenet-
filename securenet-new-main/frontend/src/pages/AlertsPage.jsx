import { useState, useEffect, useMemo } from 'react'
import { 
  Search, 
  Filter, 
  Download, 
  RefreshCw,
  AlertTriangle,
  Shield,
  Wifi,
  ChevronLeft,
  ChevronRight
} from 'lucide-react'
import { formatDistanceToNow, format } from 'date-fns'
import { api } from '../api/apiClient'
import { StatusBadge } from '../components/StatusBadge'
import { LoadingSpinner, TableSkeleton } from '../components/LoadingSpinner'
import { useDebounce } from '../hooks/useDebounce'

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

function AlertsTable({ alerts, isLoading }) {
  if (isLoading) {
    return <TableSkeleton rows={10} columns={6} />
  }

  if (alerts.length === 0) {
    return (
      <div className="text-center py-12">
        <Shield className="mx-auto h-12 w-12 text-gray-400 mb-4" />
        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
          No alerts found
        </h3>
        <p className="text-gray-600 dark:text-gray-400">
          No security alerts match your current filters.
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
              Type
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Source
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Target
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Confidence
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
          {alerts.map((alert) => {
            const Icon = attackTypeIcons[alert.attack_type] || AlertTriangle
            const attackLabel = attackTypeLabels[alert.attack_type] || alert.attack_type
            
            return (
              <tr key={alert.id} className="hover:bg-gray-50 dark:hover:bg-gray-800">
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="flex items-center">
                    <Icon className="h-5 w-5 text-danger-500 mr-3" />
                    <div>
                      <div className="text-sm font-medium text-gray-900 dark:text-white">
                        {attackLabel}
                      </div>
                      <div className="text-sm text-gray-500 dark:text-gray-400">
                        ID: {alert.id}
                      </div>
                    </div>
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="text-sm text-gray-900 dark:text-white">
                    {alert.source_ip}
                  </div>
                  <div className="text-sm text-gray-500 dark:text-gray-400">
                    {alert.source_mac}
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="text-sm text-gray-900 dark:text-white">
                    {alert.target_ip}
                  </div>
                  <div className="text-sm text-gray-500 dark:text-gray-400">
                    {alert.target_mac}
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="flex items-center">
                    <div className="text-sm font-medium text-gray-900 dark:text-white">
                      {(alert.confidence_score * 100).toFixed(0)}%
                    </div>
                    <div className="ml-2 w-16 bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                      <div
                        className="bg-primary-600 h-2 rounded-full"
                        style={{ width: `${alert.confidence_score * 100}%` }}
                      />
                    </div>
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <StatusBadge status={alert.status} />
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                  <div>{format(new Date(alert.timestamp), 'MMM d, HH:mm')}</div>
                  <div className="text-xs">
                    {formatDistanceToNow(new Date(alert.timestamp), { addSuffix: true })}
                  </div>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function Pagination({ currentPage, totalPages, onPageChange, totalItems, itemsPerPage }) {
  const startItem = (currentPage - 1) * itemsPerPage + 1
  const endItem = Math.min(currentPage * itemsPerPage, totalItems)

  return (
    <div className="flex items-center justify-between border-t border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 px-4 py-3 sm:px-6">
      <div className="flex flex-1 justify-between sm:hidden">
        <button
          onClick={() => onPageChange(currentPage - 1)}
          disabled={currentPage === 1}
          className="btn btn-secondary btn-sm"
        >
          Previous
        </button>
        <button
          onClick={() => onPageChange(currentPage + 1)}
          disabled={currentPage === totalPages}
          className="btn btn-secondary btn-sm"
        >
          Next
        </button>
      </div>
      <div className="hidden sm:flex sm:flex-1 sm:items-center sm:justify-between">
        <div>
          <p className="text-sm text-gray-700 dark:text-gray-300">
            Showing <span className="font-medium">{startItem}</span> to{' '}
            <span className="font-medium">{endItem}</span> of{' '}
            <span className="font-medium">{totalItems}</span> results
          </p>
        </div>
        <div>
          <nav className="isolate inline-flex -space-x-px rounded-md shadow-sm" aria-label="Pagination">
            <button
              onClick={() => onPageChange(currentPage - 1)}
              disabled={currentPage === 1}
              className="relative inline-flex items-center rounded-l-md px-2 py-2 text-gray-400 ring-1 ring-inset ring-gray-300 dark:ring-gray-600 hover:bg-gray-50 dark:hover:bg-gray-800 focus:z-20 focus:outline-offset-0 disabled:opacity-50"
            >
              <ChevronLeft className="h-5 w-5" />
            </button>
            
            {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
              const page = i + 1
              return (
                <button
                  key={page}
                  onClick={() => onPageChange(page)}
                  className={`relative inline-flex items-center px-4 py-2 text-sm font-semibold ${
                    currentPage === page
                      ? 'z-10 bg-primary-600 text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary-600'
                      : 'text-gray-900 dark:text-gray-300 ring-1 ring-inset ring-gray-300 dark:ring-gray-600 hover:bg-gray-50 dark:hover:bg-gray-800 focus:z-20 focus:outline-offset-0'
                  }`}
                >
                  {page}
                </button>
              )
            })}
            
            <button
              onClick={() => onPageChange(currentPage + 1)}
              disabled={currentPage === totalPages}
              className="relative inline-flex items-center rounded-r-md px-2 py-2 text-gray-400 ring-1 ring-inset ring-gray-300 dark:ring-gray-600 hover:bg-gray-50 dark:hover:bg-gray-800 focus:z-20 focus:outline-offset-0 disabled:opacity-50"
            >
              <ChevronRight className="h-5 w-5" />
            </button>
          </nav>
        </div>
      </div>
    </div>
  )
}

export default function AlertsPage() {
  const [alerts, setAlerts] = useState([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState(null)
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')
  const [typeFilter, setTypeFilter] = useState('all')
  const [currentPage, setCurrentPage] = useState(1)
  const [totalItems, setTotalItems] = useState(0)
  const itemsPerPage = 20

  const debouncedSearchTerm = useDebounce(searchTerm, 300)

  const filteredAlerts = useMemo(() => {
    return alerts.filter(alert => {
      const matchesSearch = !debouncedSearchTerm || 
        alert.source_ip.includes(debouncedSearchTerm) ||
        alert.target_ip.includes(debouncedSearchTerm) ||
        alert.source_mac.includes(debouncedSearchTerm) ||
        alert.attack_type.includes(debouncedSearchTerm)
      
      const matchesStatus = statusFilter === 'all' || alert.status === statusFilter
      const matchesType = typeFilter === 'all' || alert.attack_type === typeFilter
      
      return matchesSearch && matchesStatus && matchesType
    })
  }, [alerts, debouncedSearchTerm, statusFilter, typeFilter])

  const totalPages = Math.ceil(filteredAlerts.length / itemsPerPage)
  const paginatedAlerts = filteredAlerts.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage
  )

  const fetchAlerts = async () => {
    try {
      setIsLoading(true)
      const response = await api.security.getAlerts({ 
        limit: 100, // Fetch more for client-side filtering
        offset: 0 
      })
      setAlerts(response.data.alerts || [])
      setTotalItems(response.data.total || 0)
      setError(null)
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to fetch alerts')
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchAlerts()
  }, [])

  // Reset to first page when filters change
  useEffect(() => {
    setCurrentPage(1)
  }, [debouncedSearchTerm, statusFilter, typeFilter])

  const handleExport = () => {
    // In a real implementation, this would export to CSV/Excel
    const csvContent = [
      ['ID', 'Type', 'Source IP', 'Source MAC', 'Target IP', 'Target MAC', 'Confidence', 'Status', 'Timestamp'],
      ...filteredAlerts.map(alert => [
        alert.id,
        alert.attack_type,
        alert.source_ip,
        alert.source_mac,
        alert.target_ip,
        alert.target_mac,
        alert.confidence_score,
        alert.status,
        alert.timestamp
      ])
    ].map(row => row.join(',')).join('\n')

    const blob = new Blob([csvContent], { type: 'text/csv' })
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `security-alerts-${format(new Date(), 'yyyy-MM-dd')}.csv`
    a.click()
    window.URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Page header */}
      <div className="sm:flex sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold leading-7 text-gray-900 dark:text-white sm:truncate sm:text-3xl sm:tracking-tight">
            Security Alerts
          </h1>
          <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
            Monitor and manage security threats detected by the system
          </p>
        </div>
        <div className="mt-4 sm:ml-16 sm:mt-0 sm:flex-none">
          <button
            onClick={fetchAlerts}
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
              Search alerts
            </label>
            <div className="relative">
              <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3">
                <Search className="h-5 w-5 text-gray-400" />
              </div>
              <input
                type="text"
                placeholder="Search by IP, MAC, or type..."
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
              <option value="pending">Pending</option>
              <option value="mitigated">Mitigated</option>
              <option value="failed">Failed</option>
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
              <option value="arp_spoofing">ARP Spoofing</option>
              <option value="mac_flooding">MAC Flooding</option>
              <option value="dns_spoofing">DNS Spoofing</option>
            </select>
          </div>
        </div>

        <div className="mt-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <span className="text-sm text-gray-600 dark:text-gray-400">
              {filteredAlerts.length} of {alerts.length} alerts
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

      {/* Alerts table */}
      <div className="card overflow-hidden">
        {error ? (
          <div className="text-center py-12">
            <AlertTriangle className="mx-auto h-12 w-12 text-danger-500 mb-4" />
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
              Failed to load alerts
            </h3>
            <p className="text-gray-600 dark:text-gray-400 mb-4">{error}</p>
            <button
              onClick={fetchAlerts}
              className="btn btn-primary btn-md"
            >
              Retry
            </button>
          </div>
        ) : (
          <>
            <AlertsTable alerts={paginatedAlerts} isLoading={isLoading} />
            {!isLoading && filteredAlerts.length > 0 && (
              <Pagination
                currentPage={currentPage}
                totalPages={totalPages}
                onPageChange={setCurrentPage}
                totalItems={filteredAlerts.length}
                itemsPerPage={itemsPerPage}
              />
            )}
          </>
        )}
      </div>
    </div>
  )
}