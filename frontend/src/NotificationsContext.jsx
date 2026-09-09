import { createContext, useState, useCallback, useEffect } from 'react'

export const NotificationsContext = createContext()

export function NotificationsProvider({ children }) {
  const [notifications, setNotifications] = useState([])
  const [unreadCount, setUnreadCount] = useState(0)

  const addNotification = useCallback((message, type = 'info', timestamp = new Date()) => {
    const id = Date.now()
    const newNotification = {
      id,
      message,
      type,
      timestamp,
      read: false
    }
    setNotifications(prev => [newNotification, ...prev])
    setUnreadCount(prev => prev + 1)
    return id
  }, [])

  const markAsRead = useCallback((id) => {
    setNotifications(prev =>
      prev.map(notif =>
        notif.id === id ? { ...notif, read: true } : notif
      )
    )
    setUnreadCount(prev => Math.max(0, prev - 1))
  }, [])

  const markAllAsRead = useCallback(() => {
    setNotifications(prev =>
      prev.map(notif => ({ ...notif, read: true }))
    )
    setUnreadCount(0)
  }, [])

  const clearAll = useCallback(() => {
    setNotifications([])
    setUnreadCount(0)
  }, [])

  const removeNotification = useCallback((id) => {
    setNotifications(prev => {
      const newNotifications = prev.filter(n => n.id !== id)
      const removed = prev.find(n => n.id === id)
      if (removed && !removed.read) {
        setUnreadCount(prev => Math.max(0, prev - 1))
      }
      return newNotifications
    })
  }, [])

  return (
    <NotificationsContext.Provider
      value={{
        notifications,
        unreadCount,
        addNotification,
        markAsRead,
        markAllAsRead,
        clearAll,
        removeNotification
      }}
    >
      {children}
    </NotificationsContext.Provider>
  )
}
