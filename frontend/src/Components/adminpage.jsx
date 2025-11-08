import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './adminpage.css';

// ✅ FIXED: Proper environment variable handling
const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000';

console.log('🔗 Using API URL:', API_URL);

export default function AdminUserManagement() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [loginData, setLoginData] = useState({ username: '', password: '' });
  const [showPassword, setShowPassword] = useState(false);
  const [excelFile, setExcelFile] = useState(null);
  const [excelFileName, setExcelFileName] = useState('');
  const [users, setUsers] = useState([]);
  const [newUser, setNewUser] = useState({
    firstName: '',
    lastName: '',
    mobile: '',
    email: '',
    role: ''
  });
  const [editingUser, setEditingUser] = useState(null);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [warning, setWarning] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [loginAttempts, setLoginAttempts] = useState(0);
  const [isLocked, setIsLocked] = useState(false);
  const [sessionTimeout, setSessionTimeout] = useState(null);
  const [lastActivity, setLastActivity] = useState(Date.now());
  const [currentUser, setCurrentUser] = useState(null);
  const [authToken, setAuthToken] = useState(null);
  const [showDataWarning, setShowDataWarning] = useState(false);
  const [pendingLoginData, setPendingLoginData] = useState(null);

  const SESSION_TIMEOUT = 15 * 60 * 1000; // 15 minutes
  const MAX_LOGIN_ATTEMPTS = 3;
  const LOCK_DURATION = 5 * 60 * 1000; // 5 minutes
  const TOKEN_REFRESH_INTERVAL = 10 * 60 * 1000; // Refresh token every 10 minutes

  // ✅ FIX 4: Safe localStorage access with try-catch
  const safeLocalStorage = {
    getItem: (key) => {
      try {
        return localStorage.getItem(key);
      } catch (error) {
        console.error('localStorage getItem error:', error);
        return null;
      }
    },
    setItem: (key, value) => {
      try {
        localStorage.setItem(key, value);
        return true;
      } catch (error) {
        console.error('localStorage setItem error:', error);
        return false;
      }
    },
    removeItem: (key) => {
      try {
        localStorage.removeItem(key);
        return true;
      } catch (error) {
        console.error('localStorage removeItem error:', error);
        return false;
      }
    }
  };

  // Check for existing session on mount
  useEffect(() => {
    const token = safeLocalStorage.getItem('authToken');
    const user = safeLocalStorage.getItem('currentUser');
    const fileName = safeLocalStorage.getItem('excelFileName');
    
    if (token && user) {
      setAuthToken(token);
      setCurrentUser(user);
      setExcelFileName(fileName || '');
      setIsLoggedIn(true);
      setLastActivity(Date.now());
      fetchUsers(token);
    }
  }, []);

  // Axios interceptor for adding JWT token
  useEffect(() => {
    const interceptor = axios.interceptors.request.use(
      (config) => {
        if (authToken) {
          config.headers.Authorization = `Bearer ${authToken}`;
        }
        return config;
      },
      (error) => {
        return Promise.reject(error);
      }
    );

    return () => {
      axios.interceptors.request.eject(interceptor);
    };
  }, [authToken]);

  // ✅ FIX 2: Auto token refresh mechanism
  useEffect(() => {
    if (!isLoggedIn || !authToken) return;

    const refreshToken = async () => {
      try {
        const response = await axios.post(`${API_URL}/api/admin/refresh-token`, {}, {
          headers: { Authorization: `Bearer ${authToken}` }
        });
        
        if (response.data.success) {
          const newToken = response.data.token;
          setAuthToken(newToken);
          safeLocalStorage.setItem('authToken', newToken);
          console.log('✅ Token refreshed successfully');
        }
      } catch (error) {
        console.error('Token refresh failed:', error);
        if (error.response?.status === 401 || error.response?.status === 403) {
          handleAutoLogout();
        }
      }
    };

    // Refresh token every 10 minutes
    const refreshInterval = setInterval(refreshToken, TOKEN_REFRESH_INTERVAL);

    return () => clearInterval(refreshInterval);
  }, [isLoggedIn, authToken]);

  // Auto-logout on inactivity
  useEffect(() => {
    if (!isLoggedIn) return;

    const checkInactivity = () => {
      const now = Date.now();
      if (now - lastActivity > SESSION_TIMEOUT) {
        handleAutoLogout();
      }
    };

    const interval = setInterval(checkInactivity, 60000);

    const resetTimer = () => {
      setLastActivity(Date.now());
    };

    window.addEventListener('mousemove', resetTimer);
    window.addEventListener('keypress', resetTimer);
    window.addEventListener('click', resetTimer);

    return () => {
      clearInterval(interval);
      window.removeEventListener('mousemove', resetTimer);
      window.removeEventListener('keypress', resetTimer);
      window.removeEventListener('click', resetTimer);
    };
  }, [isLoggedIn, lastActivity]);

  const handleAutoLogout = () => {
    setIsLoggedIn(false);
    setLoginData({ username: '', password: '' });
    setCurrentUser(null);
    setAuthToken(null);
    safeLocalStorage.removeItem('authToken');
    safeLocalStorage.removeItem('currentUser');
    safeLocalStorage.removeItem('excelFileName');
    setWarning('Session expired due to inactivity. Please login again.');
    setTimeout(() => setWarning(''), 5000);
  };

  const fetchUsers = async (token) => {
    try {
      const response = await axios.get(`${API_URL}/api/users`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (response.data.success) {
        setUsers(response.data.data);
      }
    } catch (err) {
      console.error('Fetch users error:', err);
      if (err.response?.status === 401 || err.response?.status === 403) {
        handleAutoLogout();
      }
    }
  };

  const sanitizeInput = (input) => {
    if (typeof input !== 'string') return '';
    return input
      .replace(/[<>]/g, '')
      .replace(/javascript:/gi, '')
      .replace(/on\w+=/gi, '')
      .trim();
  };

  const handleFileSelect = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    if (file.size > 5 * 1024 * 1024) {
      setError('File size too large! Maximum 5MB allowed.');
      return;
    }

    const validTypes = ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/vnd.ms-excel'];
    if (!validTypes.includes(file.type) && !file.name.match(/\.(xlsx|xls)$/)) {
      setError('Invalid file type! Please upload Excel file (.xlsx or .xls)');
      return;
    }

    setExcelFile(file);
    setExcelFileName(file.name);
    setError('');
    setSuccess('Excel file selected! Now login to upload.');
    setTimeout(() => setSuccess(''), 3000);
  };

  const handleLoginConfirmation = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (isLocked) {
      setError('Account is locked due to multiple failed attempts. Please try again later.');
      return;
    }

    const username = sanitizeInput(loginData.username);
    const password = sanitizeInput(loginData.password);

    if (!username || !password) {
      setError('Please enter username and password!');
      return;
    }

    const hasPreviousData = safeLocalStorage.getItem('excelFileName');

    // Show warning if uploading new Excel (will replace data)
    if (!hasPreviousData && excelFile && users.length > 0) {
      setPendingLoginData({ username, password });
      setShowDataWarning(true);
      return;
    }

    // Proceed with login
    handleLogin({ username, password });
  };

  const confirmDataReplacement = () => {
    setShowDataWarning(false);
    if (pendingLoginData) {
      handleLogin(pendingLoginData);
      setPendingLoginData(null);
    }
  };

  const cancelDataReplacement = () => {
    setShowDataWarning(false);
    setPendingLoginData(null);
    setWarning('Login cancelled. Your existing data is safe.');
    setTimeout(() => setWarning(''), 3000);
  };

  const handleLogin = async ({ username, password }) => {
    const hasPreviousData = safeLocalStorage.getItem('excelFileName');
    let endpoint = hasPreviousData ? '/api/admin/login-only' : '/api/admin/upload-and-login';

    if (!hasPreviousData && !excelFile) {
      setError('Please select Excel file first!');
      return;
    }

    setIsLoading(true);

    try {
      let response;
      if (hasPreviousData) {
        response = await axios.post(`${API_URL}${endpoint}`, { username, password });
      } else {
        const formData = new FormData();
        formData.append('excelFile', excelFile);
        formData.append('username', username);
        formData.append('password', password);
        response = await axios.post(`${API_URL}${endpoint}`, formData, {
          headers: { 'Content-Type': 'multipart/form-data' }
        });
      }

      if (response.data.success) {
        const token = response.data.token;
        setAuthToken(token);
        setIsLoggedIn(true);
        setCurrentUser(response.data.data.username);
        setExcelFileName(response.data.data.excelFileName);
        setUsers(response.data.data.users || []);
        
        safeLocalStorage.setItem('authToken', token);
        safeLocalStorage.setItem('currentUser', response.data.data.username);
        safeLocalStorage.setItem('excelFileName', response.data.data.excelFileName);
        
        setLoginAttempts(0);
        
        // ✅ FIX 1: Show backup info if data was replaced
        if (response.data.data.backupFile) {
          setSuccess(`✅ Welcome ${username}! Backup created: ${response.data.data.backupFile}`);
        } else if (response.data.data.replacedData) {
          const { admins, users } = response.data.data.replacedData;
          setSuccess(`Welcome back, ${username}! Replaced ${admins} admins and ${users} users.`);
        } else {
          setSuccess(`Welcome back, ${username}!`);
        }
        
        setLastActivity(Date.now());
        setTimeout(() => setSuccess(''), 7000);
      }
    } catch (err) {
      const newAttempts = loginAttempts + 1;
      setLoginAttempts(newAttempts);

      setError(err.response?.data?.message || 'Login failed!');
      if (newAttempts >= MAX_LOGIN_ATTEMPTS) {
        setIsLocked(true);
        setTimeout(() => {
          setIsLocked(false);
          setLoginAttempts(0);
        }, LOCK_DURATION);
      }
    } finally {
      setIsLoading(false);
    }
  };

  // ✅ NEW: Edit User Function
  const handleEditUser = (user) => {
    setEditingUser(user);
    setNewUser({
      firstName: user.firstName,
      lastName: user.lastName,
      mobile: user.mobile,
      email: user.email,
      role: user.role
    });
    setError('');
    setSuccess('');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  // ✅ NEW: Cancel Edit Function
  const handleCancelEdit = () => {
    setEditingUser(null);
    setNewUser({
      firstName: '',
      lastName: '',
      mobile: '',
      email: '',
      role: ''
    });
    setError('');
  };

  // ✅ UPDATED: Create/Update User Function
  const handleCreateOrUpdateUser = async () => {
    if (isLoading) return;

    const { firstName, lastName, mobile, email, role } = newUser;
    if (!firstName || !lastName || !mobile || !email || !role) {
      setError('All fields are required!');
      return;
    }

    if (!/^[6-9][0-9]{9}$/.test(mobile)) {
      setError('Invalid mobile number! Must be 10 digits starting with 6-9.');
      return;
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      setError('Invalid email address!');
      return;
    }

    setIsLoading(true);
    setError('');

    try {
      let response;
      
      if (editingUser) {
        // Update existing user
        response = await axios.put(`${API_URL}/api/users/update/${editingUser._id}`, {
          firstName,
          lastName,
          mobile,
          email: email.toLowerCase(),
          role
        });
      } else {
        // Create new user
        response = await axios.post(`${API_URL}/api/users/create`, {
          firstName,
          lastName,
          mobile,
          email: email.toLowerCase(),
          role,
          createdBy: currentUser
        });
      }

      if (response.data.success) {
        setUsers(response.data.data.allUsers);
        setNewUser({ firstName: '', lastName: '', mobile: '', email: '', role: '' });
        setEditingUser(null);
        setSuccess(response.data.message);
        setTimeout(() => setSuccess(''), 3000);
      }
    } catch (err) {
      console.error('Create/Update user error:', err.response?.data);
      if (err.response?.status === 401 || err.response?.status === 403) {
        handleAutoLogout();
      } else {
        setError(err.response?.data?.message || `Failed to ${editingUser ? 'update' : 'create'} user!`);
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleDeleteUser = async (id, name) => {
    if (!window.confirm(`⚠️ Are you sure you want to delete "${name}"?\n\nThis action cannot be undone!`)) return;

    if (isLoading) return;

    setIsLoading(true);
    setError('');

    try {
      const response = await axios.delete(`${API_URL}/api/users/delete/${id}`);

      if (response.data.success) {
        setUsers(response.data.data.allUsers);
        setSuccess(response.data.message);
        setTimeout(() => setSuccess(''), 3000);
      }
    } catch (err) {
      if (err.response?.status === 401 || err.response?.status === 403) {
        handleAutoLogout();
      } else {
        setError(err.response?.data?.message || 'Failed to delete user!');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleDownloadExcel = async () => {
    if (isLoading || users.length === 0) return;

    setIsLoading(true);
    setError('');

    try {
      const response = await axios.get(`${API_URL}/api/admin/download-excel`, { 
        responseType: 'blob'
      });
      const url = URL.createObjectURL(response.data);
      const a = document.createElement('a');
      a.href = url;
      a.download = `users_backup_${Date.now()}.xlsx`;
      a.click();
      URL.revokeObjectURL(url);
      setSuccess('✅ Excel downloaded! ⚠️ IMPORTANT: Replace ALL passwords in Admin sheet before re-uploading!');
      setTimeout(() => setSuccess(''), 7000);
    } catch (err) {
      if (err.response?.status === 401 || err.response?.status === 403) {
        handleAutoLogout();
      } else {
        setError(err.response?.data?.message || 'Failed to download Excel!');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogout = () => {
    setIsLoggedIn(false);
    setLoginData({ username: '', password: '' });
    setCurrentUser(null);
    setAuthToken(null);
    setUsers([]);
    setExcelFileName('');
    setEditingUser(null);
    setNewUser({ firstName: '', lastName: '', mobile: '', email: '', role: '' });
    safeLocalStorage.removeItem('authToken');
    safeLocalStorage.removeItem('currentUser');
    safeLocalStorage.removeItem('excelFileName');
    setWarning('Logged out successfully.');
    setTimeout(() => setWarning(''), 3000);
  };

  const togglePasswordVisibility = () => {
    setShowPassword(!showPassword);
  };

  const DataWarningModal = () => (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      background: 'rgba(0,0,0,0.7)',
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      zIndex: 9999
    }}>
      <div style={{
        background: 'white',
        padding: '30px',
        borderRadius: '15px',
        maxWidth: '500px',
        width: '90%',
        boxShadow: '0 10px 40px rgba(0,0,0,0.3)'
      }}>
        <h2 style={{ color: '#dc3545', marginBottom: '20px' }}>⚠️ Data Replacement Warning!</h2>
        <div className="warning" style={{ textAlign: 'left', marginBottom: '20px' }}>
          <strong>This action will:</strong>
          <ul style={{ marginTop: '10px', marginLeft: '20px' }}>
            <li>✅ Create automatic backup of current data</li>
            <li>❌ Delete ALL existing admin accounts</li>
            <li>❌ Delete ALL existing users ({users.length} users)</li>
            <li>🔄 Replace with data from the uploaded Excel file</li>
          </ul>
          <p style={{ marginTop: '15px', fontWeight: 'bold', color: '#28a745' }}>
            💾 Backup will be saved in backups/ folder
          </p>
        </div>
        <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
          <button 
            className="btn btn-secondary" 
            onClick={cancelDataReplacement}
            style={{ width: 'auto', padding: '12px 25px' }}
          >
            ❌ Cancel
          </button>
          <button 
            className="btn btn-danger" 
            onClick={confirmDataReplacement}
            style={{ width: 'auto', padding: '12px 25px' }}
          >
            ✅ Yes, Replace Data
          </button>
        </div>
      </div>
    </div>
  );

  // Login Form Render
  if (!isLoggedIn) {
    return (
      <>
        {showDataWarning && <DataWarningModal />}
        <div className="app-container">
          <div className="login-box">
            <h1>🔐 Admin Login</h1>

            <div className="info-box">
              💾 Secure login with Excel upload. Passwords are hashed with bcrypt. JWT authentication with auto-refresh enabled.
            </div>

            {excelFile && (
              <div className="warning">
                ⚠️ Uploading a new Excel file will REPLACE all existing data! (Backup will be created automatically)
              </div>
            )}

            <div className="file-upload">
              <label htmlFor="excelFile">📄 Upload Excel File (Max 5MB)</label>
              <input
                type="file"
                id="excelFile"
                accept=".xlsx,.xls"
                onChange={handleFileSelect}
                disabled={isLoading}
              />
              {excelFileName && <p style={{ fontSize: '12px', color: '#28a745', marginTop: '5px' }}>✅ Selected: {excelFileName}</p>}
            </div>

            <form onSubmit={handleLoginConfirmation}>
              <div className="form-group password-field">
                <label>Username</label>
                <input
                  type="text"
                  value={loginData.username}
                  onChange={(e) => setLoginData({ ...loginData, username: e.target.value })}
                  placeholder="Enter username"
                  disabled={isLoading}
                  maxLength="50"
                />
              </div>

              <div className="form-group password-field">
                <label>Password</label>
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={loginData.password}
                  onChange={(e) => setLoginData({ ...loginData, password: e.target.value })}
                  placeholder="Enter password"
                  disabled={isLoading}
                  maxLength="100"
                />
                <span className="password-toggle" onClick={togglePasswordVisibility}>
                  {showPassword ? '🙈' : '👁️'}
                </span>
              </div>

              <button type="submit" className="btn btn-primary" disabled={isLoading || isLocked}>
                {isLoading ? '⏳ Logging in...' : '🔓 Login & Upload'}
              </button>

              {loginAttempts > 0 && (
                <div className="attempt-warning">
                  ⚠️ Failed attempts: {loginAttempts}/{MAX_LOGIN_ATTEMPTS}
                </div>
              )}

              {isLocked && (
                <div className="error">
                  ❌ Account locked! Try again in {Math.ceil(LOCK_DURATION / 60000)} minutes.
                </div>
              )}
            </form>

            {error && <div className="error">❌ {error}</div>}
            {success && <div className="success">✅ {success}</div>}
            {warning && <div className="warning">⚠️ {warning}</div>}
          </div>
        </div>
      </>
    );
  }

  // Dashboard Render
  return (
    <div className="app-container">
      <div className="logout-btn-container">
        <button className="btn btn-secondary btn-small" onClick={handleLogout}>
          🚪 Logout
        </button>
      </div>

      <div className="dashboard-box">
        <h1>👨‍💼 Secure Admin Dashboard</h1>
        
        <div className="session-info">
          <span>👤 Logged in as: <strong>{currentUser}</strong></span>
          <span>🕐 Session active (Auto-refresh enabled)</span>
        </div>

        <div className="info-box">
          💾 Data stored in MongoDB. File: <strong>{excelFileName}</strong><br/>
          🔒 Security: JWT Auth (Auto-refresh) + Bcrypt + Rate Limiting<br/>
          📦 Backups: Auto-created before data replacement
        </div>

        {users.length > 0 && (
          <div className="stats-box">
            📊 Total Users: {users.length} | Last Activity: {new Date(lastActivity).toLocaleTimeString()}
          </div>
        )}

        <h2>{editingUser ? '✏️ Edit User' : '➕ Create New User'}</h2>

        {editingUser && (
          <div className="warning" style={{ marginBottom: '15px' }}>
            ✏️ Editing: <strong>{editingUser.firstName} {editingUser.lastName}</strong>
            <button 
              className="btn btn-secondary" 
              onClick={handleCancelEdit}
              style={{ marginLeft: '10px', padding: '5px 15px', fontSize: '12px' }}
            >
              ❌ Cancel Edit
            </button>
          </div>
        )}

        <div className="form-group">
          <label>First Name *</label>
          <input
            type="text"
            value={newUser.firstName}
            onChange={(e) => setNewUser({...newUser, firstName: e.target.value})}
            placeholder="Enter first name"
            maxLength="50"
            disabled={isLoading}
          />
        </div>

        <div className="form-group">
          <label>Last Name *</label>
          <input
            type="text"
            value={newUser.lastName}
            onChange={(e) => setNewUser({...newUser, lastName: e.target.value})}
            placeholder="Enter last name"
            maxLength="50"
            disabled={isLoading}
          />
        </div>

        <div className="form-group">
          <label>Mobile Number * (Indian: 10 digits, starts with 6-9)</label>
          <input
            type="tel"
            value={newUser.mobile}
            onChange={(e) => setNewUser({...newUser, mobile: e.target.value.replace(/\D/g, '').slice(0, 10)})}
            placeholder="Enter mobile number"
            maxLength="10"
            disabled={isLoading}
          />
        </div>

        <div className="form-group">
          <label>Email ID *</label>
          <input
            type="email"
            value={newUser.email}
            onChange={(e) => setNewUser({...newUser, email: e.target.value})}
            placeholder="Enter email address"
            maxLength="100"
            disabled={isLoading}
          />
        </div>

        <div className="form-group">
          <label>Role *</label>
          <select
            value={newUser.role}
            onChange={(e) => setNewUser({...newUser, role: e.target.value})}
            disabled={isLoading}
          >
            <option value="">Select Role</option>
            <option value="Admin">Admin</option>
            <option value="User">User</option>
            <option value="Manager">Manager</option>
            <option value="Employee">Employee</option>
            <option value="Supervisor">Supervisor</option>
          </select>
        </div>

        <button 
          className="btn btn-success" 
          onClick={handleCreateOrUpdateUser}
          disabled={isLoading}
        >
          {isLoading ? '⏳ Processing...' : editingUser ? '✅ Update User' : '✅ Create User (Save to Database)'}
        </button>

        {users.length > 0 && (
          <button 
            className="btn btn-download" 
            onClick={handleDownloadExcel}
            disabled={isLoading}
          >
            {isLoading ? '⏳ Downloading...' : `📥 Download Excel (${users.length} users)`}
          </button>
        )}

        {error && <div className="error">❌ {error}</div>}
        {success && <div className="success">✅ {success}</div>}
        {warning && <div className="warning">⚠️ {warning}</div>}

        {users.length > 0 && (
          <div className="user-list">
            <h3 style={{marginBottom: '15px', color: '#333', fontSize: '18px'}}>
              👥 All Users ({users.length})
            </h3>
            {users.map((user) => (
              <div key={user._id} className="user-item">
                <div className="user-info">
                  <h4>{user.firstName} {user.lastName}</h4>
                  <p>📱 {user.mobile}</p>
                  <p>📧 {user.email}</p>
                  <p>👤 Role: <strong>{user.role}</strong></p>
                  <p>🕐 Created: {new Date(user.createdAt).toLocaleString('en-IN')}</p>
                  <p>👨‍💼 Created by: {user.createdBy}</p>
                </div>
                <div className="user-actions">
                  <button 
                    className="btn btn-secondary" 
                    onClick={() => handleEditUser(user)}
                    disabled={isLoading}
                    style={{ background: '#17a2b8' }}
                  >
                    ✏️ Edit
                  </button>
                  <button 
                    className="btn btn-danger" 
                    onClick={() => handleDeleteUser(user._id, `${user.firstName} ${user.lastName}`)}
                    disabled={isLoading}
                  >
                    🗑️ Delete
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}