// End-user enrollment portal (enroll.html#/t/<token>). Separate entry from the console: no session, no providers.
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import '@fontsource-variable/hanken-grotesk'
import '@fontsource-variable/red-hat-mono'
import '../app/theme.css'
import './enroll.css'
import { EnrollApp } from './App'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <EnrollApp />
  </StrictMode>,
)
