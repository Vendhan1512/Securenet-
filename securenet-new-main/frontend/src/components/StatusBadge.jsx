import { clsx } from 'clsx'

const statusConfig = {
  success: {
    className: 'status-success',
    label: 'Success',
  },
  warning: {
    className: 'status-warning',
    label: 'Warning',
  },
  danger: {
    className: 'status-danger',
    label: 'Danger',
  },
  info: {
    className: 'status-info',
    label: 'Info',
  },
  // System specific statuses
  running: {
    className: 'status-success',
    label: 'Running',
  },
  stopped: {
    className: 'status-danger',
    label: 'Stopped',
  },
  degraded: {
    className: 'status-warning',
    label: 'Degraded',
  },
  error: {
    className: 'status-danger',
    label: 'Error',
  },
  // Monitoring statuses
  active: {
    className: 'status-success',
    label: 'Active',
  },
  inactive: {
    className: 'status-danger',
    label: 'Inactive',
  },
  // Alert statuses
  mitigated: {
    className: 'status-success',
    label: 'Mitigated',
  },
  pending: {
    className: 'status-warning',
    label: 'Pending',
  },
  failed: {
    className: 'status-danger',
    label: 'Failed',
  },
}

export function StatusBadge({ status, children, className = '' }) {
  const config = statusConfig[status] || statusConfig.info
  
  return (
    <span
      className={clsx(
        'status-indicator',
        config.className,
        className
      )}
    >
      {children || config.label}
    </span>
  )
}

export function SystemStatusBadge({ systemState, monitoringActive }) {
  if (!monitoringActive) {
    return <StatusBadge status="inactive">Inactive</StatusBadge>
  }
  
  return <StatusBadge status={systemState}>{systemState}</StatusBadge>
}