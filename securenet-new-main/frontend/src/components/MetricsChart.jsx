import { useMemo } from 'react'
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts'
import { useSystemStore } from '../stores/systemStore'

// Generate mock historical data for demonstration
function generateMockData() {
  const now = new Date()
  const data = []
  
  for (let i = 23; i >= 0; i--) {
    const time = new Date(now.getTime() - i * 60 * 60 * 1000)
    data.push({
      time: time.toLocaleTimeString('en-US', { 
        hour: '2-digit', 
        minute: '2-digit' 
      }),
      threats: Math.floor(Math.random() * 10),
      mitigations: Math.floor(Math.random() * 8),
      responseTime: 50 + Math.random() * 100,
    })
  }
  
  return data
}

export function MetricsChart() {
  const { metrics } = useSystemStore()
  
  const chartData = useMemo(() => {
    // In a real implementation, this would come from the API
    // For now, we'll generate mock data
    return generateMockData()
  }, [])

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-white dark:bg-gray-800 p-3 border border-gray-200 dark:border-gray-700 rounded-lg shadow-lg">
          <p className="text-sm font-medium text-gray-900 dark:text-white mb-2">
            {label}
          </p>
          {payload.map((entry, index) => (
            <p
              key={index}
              className="text-sm"
              style={{ color: entry.color }}
            >
              {entry.name}: {entry.value}
              {entry.dataKey === 'responseTime' && 'ms'}
            </p>
          ))}
        </div>
      )
    }
    return null
  }

  return (
    <div className="h-64">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={chartData}>
          <CartesianGrid 
            strokeDasharray="3 3" 
            className="stroke-gray-200 dark:stroke-gray-700" 
          />
          <XAxis 
            dataKey="time" 
            className="text-xs fill-gray-600 dark:fill-gray-400"
          />
          <YAxis 
            yAxisId="left"
            className="text-xs fill-gray-600 dark:fill-gray-400"
          />
          <YAxis 
            yAxisId="right"
            orientation="right"
            className="text-xs fill-gray-600 dark:fill-gray-400"
          />
          <Tooltip content={<CustomTooltip />} />
          <Legend 
            wrapperStyle={{ 
              fontSize: '12px',
              color: 'var(--text-color)'
            }}
          />
          <Line
            type="monotone"
            dataKey="threats"
            stroke="#ef4444"
            strokeWidth={2}
            dot={{ r: 3 }}
            name="Threats"
            yAxisId="left"
          />
          <Line
            type="monotone"
            dataKey="mitigations"
            stroke="#22c55e"
            strokeWidth={2}
            dot={{ r: 3 }}
            name="Mitigations"
            yAxisId="left"
          />
          <Line
            type="monotone"
            dataKey="responseTime"
            stroke="#3b82f6"
            strokeWidth={2}
            dot={{ r: 3 }}
            name="Response Time (ms)"
            yAxisId="right"
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}