import { useContext, useState, useRef, useEffect } from 'react'
import { NotificationsContext } from '../NotificationsContext'
import { Bell, X, CheckCheck, Trash2 } from 'lucide-react'

export default function NotificationBell() {
  const { notifications, unreadCount, markAsRead, markAllAsRead, removeNotification, clearAll } = useContext(NotificationsContext)
  const [isOpen, setIsOpen] = useState(false)
  const dropdownRef = useRef(null)

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setIsOpen(false)
      }
    }

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside)
      return () => document.removeEventListener('mousedown', handleClickOutside)
    }
  }, [isOpen])

  const getNotificationIcon = (type) => {
    switch (type) {
      case 'login':
        return '🔐'
      case 'scan_started':
        return '🔍'
      case 'scan_finished':
        return '✅'
      case 'error':
        return '❌'
      case 'warning':
        return '⚠️'
      case 'success':
        return '✨'
      default:
        return 'ℹ️'
    }
  }

  const getNotificationColor = (type) => {
    switch (type) {
      case 'login':
        return 'bg-blue-50 border-blue-200'
      case 'scan_started':
        return 'bg-orange-50 border-orange-200'
      case 'scan_finished':
        return 'bg-green-50 border-green-200'
      case 'error':
        return 'bg-red-50 border-red-200'
      case 'warning':
        return 'bg-yellow-50 border-yellow-200'
      case 'success':
        return 'bg-teal-50 border-teal-200'
      default:
        return 'bg-slate-50 border-slate-200'
    }
  }

  const formatTime = (timestamp) => {
    const now = new Date()
    const diff = now - new Date(timestamp)
    const seconds = Math.floor(diff / 1000)
    const minutes = Math.floor(seconds / 60)
    const hours = Math.floor(minutes / 60)
    const days = Math.floor(hours / 24)

    if (seconds < 60) return 'just now'
    if (minutes < 60) return `${minutes}m ago`
    if (hours < 24) return `${hours}h ago`
    if (days < 7) return `${days}d ago`

    return new Date(timestamp).toLocaleDateString()
  }

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="relative p-2 hover:bg-orange-700/50 rounded-lg transition-colors"
        title="Notifications"
      >
        <Bell className="w-6 h-6 text-white" />

        {unreadCount > 0 && (
          <span className="absolute top-0 right-0 flex items-center justify-center w-5 h-5 bg-red-500 text-white text-xs font-bold rounded-full">
            {unreadCount > 99 ? '99+' : unreadCount}
          </span>
        )}
      </button>

      {isOpen && (
        <div className="fixed top-24 right-4 bg-white rounded-lg shadow-2xl border border-slate-200 z-50 flex flex-col overflow-hidden animate-fade-in" style={{ width: '450px', maxHeight: '75vh' }}>
          <div className="bg-gradient-to-r from-orange-600 to-amber-500 text-white p-4 flex items-center justify-between">
            <h3 className="font-bold text-sm">Notifications</h3>
            <div className="flex gap-2">
              {unreadCount > 0 && (
                <button
                  onClick={markAllAsRead}
                  className="p-1 hover:bg-orange-700/50 rounded transition-colors"
                  title="Mark all as read"
                >
                  <CheckCheck className="w-4 h-4" />
                </button>
              )}
              <button
                onClick={() => setIsOpen(false)}
                className="p-1 hover:bg-orange-700/50 rounded transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto">
            {notifications.length === 0 ? (
              <div className="p-8 text-center text-slate-500">
                <Bell className="w-8 h-8 mx-auto mb-2 text-slate-400" />
                <p className="text-sm">No notifications yet</p>
              </div>
            ) : (
              <div className="divide-y divide-slate-200">
                {notifications.map((notif) => (
                  <div
                    key={notif.id}
                    className={`p-4 border-l-4 transition-colors hover:bg-slate-50 ${
                      notif.read
                        ? 'bg-white border-l-slate-300'
                        : 'bg-slate-50 border-l-orange-500'
                    }`}
                    onClick={() => !notif.read && markAsRead(notif.id)}
                  >
                    <div className="flex items-start gap-3">
                      <span className="text-lg flex-shrink-0 mt-0.5">
                        {getNotificationIcon(notif.type)}
                      </span>

                      <div className="flex-1 min-w-0">
                        <p className={`text-sm font-medium break-words ${
                          notif.read ? 'text-slate-600' : 'text-slate-900'
                        }`}>
                          {notif.message}
                        </p>
                        <p className="text-xs text-slate-500 mt-1">
                          {formatTime(notif.timestamp)}
                        </p>
                      </div>

                      <div className="flex items-center gap-2 flex-shrink-0">
                        {!notif.read && (
                          <span className="w-2 h-2 bg-orange-500 rounded-full"></span>
                        )}
                        <button
                          onClick={(e) => {
                            e.stopPropagation()
                            removeNotification(notif.id)
                          }}
                          className="p-1 hover:bg-red-100 rounded transition-colors"
                          title="Delete"
                        >
                          <X className="w-3.5 h-3.5 text-slate-400 hover:text-red-600" />
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {notifications.length > 0 && (
            <div className="bg-slate-50 border-t border-slate-200 p-3 flex justify-center">
              <button
                onClick={clearAll}
                className="flex items-center gap-2 px-3 py-2 text-xs font-bold text-red-600 hover:bg-red-50 rounded transition-colors"
              >
                <Trash2 className="w-3.5 h-3.5" />
                Clear All
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
