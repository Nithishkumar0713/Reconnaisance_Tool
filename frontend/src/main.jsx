import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import { BackgroundScansProvider } from './BackgroundScansContext'
import { NotificationsProvider } from './NotificationsContext'
import './styles.css'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <NotificationsProvider>
      <BackgroundScansProvider>
        <App />
      </BackgroundScansProvider>
    </NotificationsProvider>
  </React.StrictMode>,
)
