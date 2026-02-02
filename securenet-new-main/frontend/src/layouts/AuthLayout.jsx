import { Outlet } from 'react-router-dom'
import { Shield } from 'lucide-react'

export function AuthLayout() {
  return (
    <div className="min-h-screen flex">
      {/* Left side - Branding */}
      <div className="hidden lg:flex lg:flex-1 lg:flex-col lg:justify-center lg:px-8 bg-primary-600">
        <div className="mx-auto w-full max-w-sm">
          <div className="text-center">
            <Shield className="mx-auto h-16 w-16 text-white mb-6" />
            <h1 className="text-3xl font-bold text-white mb-4">
              LAN Security System
            </h1>
            <p className="text-primary-100 text-lg leading-relaxed">
              Advanced network monitoring and threat detection system for enterprise security.
            </p>
          </div>
          
          <div className="mt-12 space-y-6">
            <div className="flex items-center text-primary-100">
              <div className="flex-shrink-0 w-2 h-2 bg-primary-300 rounded-full mr-3"></div>
              <span>Real-time threat detection</span>
            </div>
            <div className="flex items-center text-primary-100">
              <div className="flex-shrink-0 w-2 h-2 bg-primary-300 rounded-full mr-3"></div>
              <span>Automated response system</span>
            </div>
            <div className="flex items-center text-primary-100">
              <div className="flex-shrink-0 w-2 h-2 bg-primary-300 rounded-full mr-3"></div>
              <span>Comprehensive audit logging</span>
            </div>
          </div>
        </div>
      </div>

      {/* Right side - Auth forms */}
      <div className="flex flex-1 flex-col justify-center px-4 py-12 sm:px-6 lg:flex-none lg:px-20 xl:px-24">
        <div className="mx-auto w-full max-w-sm lg:w-96">
          {/* Mobile branding */}
          <div className="lg:hidden text-center mb-8">
            <Shield className="mx-auto h-12 w-12 text-primary-600 mb-4" />
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
              LAN Security System
            </h1>
          </div>
          
          <Outlet />
        </div>
      </div>
    </div>
  )
}