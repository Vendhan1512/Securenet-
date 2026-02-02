import { useState, useEffect } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Eye, EyeOff, LogIn } from 'lucide-react'
import { useAuthStore } from '../stores/authStore'
import { LoadingSpinner } from '../components/LoadingSpinner'

const loginSchema = z.object({
  username: z.string().min(1, 'Username is required'),
  password: z.string().min(1, 'Password is required'),
})

export default function LoginPage() {
  const [showPassword, setShowPassword] = useState(false)
  const { login, isAuthenticated, isLoading, error, clearError } = useAuthStore()
  const location = useLocation()

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm({
    resolver: zodResolver(loginSchema),
    defaultValues: {
      username: '',
      password: '',
    },
  })

  // Clear error when component mounts
  useEffect(() => {
    clearError()
  }, [clearError])

  // Redirect if already authenticated
  if (isAuthenticated) {
    const from = location.state?.from?.pathname || '/dashboard'
    return <Navigate to={from} replace />
  }

  const onSubmit = async (data) => {
    await login(data)
  }

  return (
    <div className="animate-fade-in">
      <div>
        <h2 className="text-2xl font-bold leading-9 tracking-tight text-gray-900 dark:text-white">
          Sign in to your account
        </h2>
        <p className="mt-2 text-sm leading-6 text-gray-600 dark:text-gray-400">
          Access the LAN Security System dashboard
        </p>
      </div>

      <div className="mt-8">
        <form className="space-y-6" onSubmit={handleSubmit(onSubmit)}>
          {/* Username */}
          <div>
            <label
              htmlFor="username"
              className="block text-sm font-medium leading-6 text-gray-900 dark:text-white"
            >
              Username
            </label>
            <div className="mt-2">
              <input
                {...register('username')}
                type="text"
                autoComplete="username"
                className="input"
                placeholder="Enter your username"
              />
              {errors.username && (
                <p className="mt-2 text-sm text-danger-600 dark:text-danger-400">
                  {errors.username.message}
                </p>
              )}
            </div>
          </div>

          {/* Password */}
          <div>
            <label
              htmlFor="password"
              className="block text-sm font-medium leading-6 text-gray-900 dark:text-white"
            >
              Password
            </label>
            <div className="mt-2 relative">
              <input
                {...register('password')}
                type={showPassword ? 'text' : 'password'}
                autoComplete="current-password"
                className="input pr-10"
                placeholder="Enter your password"
              />
              <button
                type="button"
                className="absolute inset-y-0 right-0 flex items-center pr-3"
                onClick={() => setShowPassword(!showPassword)}
              >
                {showPassword ? (
                  <EyeOff className="h-4 w-4 text-gray-400" />
                ) : (
                  <Eye className="h-4 w-4 text-gray-400" />
                )}
              </button>
            </div>
            {errors.password && (
              <p className="mt-2 text-sm text-danger-600 dark:text-danger-400">
                {errors.password.message}
              </p>
            )}
          </div>

          {/* Error message */}
          {error && (
            <div className="rounded-md bg-danger-50 dark:bg-danger-900/50 p-4">
              <p className="text-sm text-danger-800 dark:text-danger-200">
                {error}
              </p>
            </div>
          )}

          {/* Submit button */}
          <div>
            <button
              type="submit"
              disabled={isSubmitting || isLoading}
              className="btn btn-primary btn-md w-full flex justify-center items-center gap-2"
            >
              {isSubmitting || isLoading ? (
                <LoadingSpinner size="sm" />
              ) : (
                <LogIn className="h-4 w-4" />
              )}
              Sign in
            </button>
          </div>
        </form>

        {/* Demo credentials */}
        <div className="mt-8 p-4 bg-gray-50 dark:bg-gray-800 rounded-md">
          <h3 className="text-sm font-medium text-gray-900 dark:text-white mb-2">
            Demo Credentials
          </h3>
          <div className="text-xs text-gray-600 dark:text-gray-400 space-y-1">
            <div>Admin: <code>admin</code> / <code>admin123</code></div>
            <div>Operator: <code>operator</code> / <code>operator123</code></div>
          </div>
        </div>
      </div>
    </div>
  )
}