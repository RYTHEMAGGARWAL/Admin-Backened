const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const rateLimit = require('express-rate-limit');

// Load environment variables
dotenv.config();

// Import routes
const adminRoutes = require('./routes/adminRoutes');
const userRoutes = require('./routes/userRoutes');

// Initialize express app
const app = express();

// ✅ CORS Configuration with credentials
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate Limiting for login endpoints
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: {
    success: false,
    message: 'Too many login attempts! Please try again after 15 minutes.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// General API rate limiter
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window
  message: {
    success: false,
    message: 'Too many requests! Please try again later.'
  }
});

// Apply rate limiting
app.use('/api/admin/login-only', loginLimiter);
app.use('/api/admin/upload-and-login', loginLimiter);
app.use('/api/', apiLimiter);

// Create uploads directory if not exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  console.log('✅ Uploads directory created');
}

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (ext !== '.xlsx' && ext !== '.xls') {
      return cb(new Error('Only Excel files (.xlsx or .xls) are allowed!'));
    }
    cb(null, true);
  }
});

// Make upload available globally
app.set('upload', upload);

// Load environment variables
require('dotenv').config();

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => {
  console.log('✅ MongoDB Connected Successfully!');
})
.catch((err) => {
  console.error('❌ MongoDB Connection Error:', err.message);
  process.exit(1);
});

// MongoDB connection event handlers
mongoose.connection.on('disconnected', () => {
  console.warn('⚠️ MongoDB disconnected! Attempting reconnect...');
});

mongoose.connection.on('reconnected', () => {
  console.log('✅ MongoDB reconnected successfully!');
});

mongoose.connection.on('error', (err) => {
  console.error('❌ MongoDB runtime error:', err);
});

// Routes
app.use('/api/admin', adminRoutes);
app.use('/api/users', userRoutes);

// Health check route
app.get('/', (req, res) => {
  res.json({ 
    success: true,
    message: '🚀 Admin User Management API Running!',
    endpoints: {
      admin_login: 'POST /api/admin/login-only',
      admin_upload: 'POST /api/admin/upload-and-login',
      admin_download: 'GET /api/admin/download-excel',
      users: '/api/users',
      create_user: 'POST /api/users/create',
      delete_user: 'DELETE /api/users/delete/:id'
    },
    security: {
      rate_limiting: 'Enabled',
      password_hashing: 'Bcrypt',
      authentication: 'JWT',
      cors: 'Configured'
    }
  });
});

// ✅ Health check with database status (SINGLE VERSION)
app.get('/api/health', async (req, res) => {
  try {
    await mongoose.connection.db.admin().ping();
    res.json({ 
      success: true, 
      message: 'System healthy',
      database: 'connected',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(503).json({ 
      success: false, 
      message: 'Database unavailable',
      database: 'disconnected',
      error: error.message
    });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found!'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err.message);
  
  // Multer errors
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        success: false,
        message: 'File size too large! Maximum 5MB allowed.'
      });
    }
    return res.status(400).json({
      success: false,
      message: err.message
    });
  }

  // MongoDB connection errors
  if (err.name === 'MongoNetworkError' || err.name === 'MongoTimeoutError') {
    return res.status(503).json({
      success: false,
      message: 'Database connection error! Please try again later.'
    });
  }

  // Generic errors
  res.status(500).json({ 
    success: false,
    message: 'Something went wrong!' 
  });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📁 Uploads directory: ${uploadsDir}`);
  console.log(`🔒 Security features enabled: Rate Limiting, JWT, Bcrypt, CORS`);
  console.log(`🌐 Allowing requests from: ${process.env.FRONTEND_URL || 'http://localhost:5173'}`);
});