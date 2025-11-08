import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'

import AdminPage from './Components/adminpage.jsx';

createRoot(document.getElementById('root')).render(
  <StrictMode>
 
    <AdminPage />
  </StrictMode>,
)
