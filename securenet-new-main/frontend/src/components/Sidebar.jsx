import { Fragment } from 'react'
import { Dialog, Transition } from '@headlessui/react'
import { NavLink, useLocation } from 'react-router-dom'
import { clsx } from 'clsx'
import {
  Shield,
  LayoutDashboard,
  AlertTriangle,
  ShieldCheck,
  Activity,
  FileText,
  Settings,
  X,
} from 'lucide-react'

const navigation = [
  { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Security Alerts', href: '/alerts', icon: AlertTriangle },
  { name: 'Mitigations', href: '/mitigations', icon: ShieldCheck },
  { name: 'System Status', href: '/system', icon: Activity },
  { name: 'Logs', href: '/logs', icon: FileText },
  { name: 'Settings', href: '/settings', icon: Settings },
]

function SidebarContent({ onClose = () => {} }) {
  const location = useLocation()

  return (
    <div className="flex grow flex-col gap-y-5 overflow-y-auto bg-white dark:bg-gray-800 px-6 pb-4 border-r border-gray-200 dark:border-gray-700">
      {/* Logo */}
      <div className="flex h-16 shrink-0 items-center">
        <Shield className="h-8 w-8 text-primary-600" />
        <span className="ml-2 text-xl font-semibold text-gray-900 dark:text-white">
          LAN Security
        </span>
      </div>

      {/* Navigation */}
      <nav className="flex flex-1 flex-col">
        <ul role="list" className="flex flex-1 flex-col gap-y-7">
          <li>
            <ul role="list" className="-mx-2 space-y-1">
              {navigation.map((item) => {
                const isActive = location.pathname === item.href
                return (
                  <li key={item.name}>
                    <NavLink
                      to={item.href}
                      onClick={onClose}
                      className={clsx(
                        'group flex gap-x-3 rounded-md p-2 text-sm leading-6 font-semibold transition-colors',
                        isActive
                          ? 'bg-primary-50 text-primary-700 dark:bg-primary-900/50 dark:text-primary-300'
                          : 'text-gray-700 hover:text-primary-700 hover:bg-gray-50 dark:text-gray-300 dark:hover:text-primary-300 dark:hover:bg-gray-700'
                      )}
                    >
                      <item.icon
                        className={clsx(
                          'h-6 w-6 shrink-0',
                          isActive
                            ? 'text-primary-700 dark:text-primary-300'
                            : 'text-gray-400 group-hover:text-primary-700 dark:text-gray-400 dark:group-hover:text-primary-300'
                        )}
                        aria-hidden="true"
                      />
                      {item.name}
                    </NavLink>
                  </li>
                )
              })}
            </ul>
          </li>
        </ul>
      </nav>
    </div>
  )
}

export function Sidebar({ open, onClose }) {
  return (
    <>
      {/* Mobile sidebar */}
      <Transition.Root show={open} as={Fragment}>
        <Dialog as="div" className="relative z-50 lg:hidden" onClose={onClose}>
          <Transition.Child
            as={Fragment}
            enter="transition-opacity ease-linear duration-300"
            enterFrom="opacity-0"
            enterTo="opacity-100"
            leave="transition-opacity ease-linear duration-300"
            leaveFrom="opacity-100"
            leaveTo="opacity-0"
          >
            <div className="fixed inset-0 bg-gray-900/80" />
          </Transition.Child>

          <div className="fixed inset-0 flex">
            <Transition.Child
              as={Fragment}
              enter="transition ease-in-out duration-300 transform"
              enterFrom="-translate-x-full"
              enterTo="translate-x-0"
              leave="transition ease-in-out duration-300 transform"
              leaveFrom="translate-x-0"
              leaveTo="-translate-x-full"
            >
              <Dialog.Panel className="relative mr-16 flex w-full max-w-xs flex-1">
                <Transition.Child
                  as={Fragment}
                  enter="ease-in-out duration-300"
                  enterFrom="opacity-0"
                  enterTo="opacity-100"
                  leave="ease-in-out duration-300"
                  leaveFrom="opacity-100"
                  leaveTo="opacity-0"
                >
                  <div className="absolute left-full top-0 flex w-16 justify-center pt-5">
                    <button
                      type="button"
                      className="-m-2.5 p-2.5"
                      onClick={onClose}
                    >
                      <span className="sr-only">Close sidebar</span>
                      <X className="h-6 w-6 text-white" aria-hidden="true" />
                    </button>
                  </div>
                </Transition.Child>
                <SidebarContent onClose={onClose} />
              </Dialog.Panel>
            </Transition.Child>
          </div>
        </Dialog>
      </Transition.Root>

      {/* Desktop sidebar */}
      <div className="hidden lg:fixed lg:inset-y-0 lg:z-50 lg:flex lg:w-64 lg:flex-col">
        <SidebarContent />
      </div>
    </>
  )
}