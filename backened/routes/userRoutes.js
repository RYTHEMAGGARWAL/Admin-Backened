const express = require('express');
const router = express.Router();
const User = require('../models/User');
const jwt = require('jsonwebtoken');

// ✅ INPUT SANITIZATION HELPER
const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  return input
    .replace(/[<>]/g, '') // Remove HTML tags
    .replace(/javascript:/gi, '') // Remove javascript: protocol
    .replace(/on\w+=/gi, '') // Remove event handlers
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;')
    .trim();
};

// ✅ VALIDATION HELPERS
const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const validateMobile = (mobile) => {
  const mobileRegex = /^[6-9][0-9]{9}$/;
  return mobileRegex.test(mobile);
};

const validateRole = (role) => {
  const validRoles = ['Admin', 'User', 'Manager', 'Employee', 'Supervisor'];
  return validRoles.includes(role);
};

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'Access token required!' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Invalid or expired token!' });
    }
    req.user = user;
    next();
  });
};

// Get all users (Protected)
router.get('/', authenticateToken, async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 });
    
    res.json({
      success: true,
      count: users.length,
      data: users
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error!' 
    });
  }
});

// Create new user (Protected)
router.post('/create', authenticateToken, async (req, res) => {
  try {
    // ✅ Sanitize all inputs
    const firstName = sanitizeInput(req.body.firstName);
    const lastName = sanitizeInput(req.body.lastName);
    const mobile = sanitizeInput(req.body.mobile);
    const email = sanitizeInput(req.body.email);
    const role = sanitizeInput(req.body.role);
    const createdBy = sanitizeInput(req.body.createdBy);

    // ✅ Validate required fields
    if (!firstName || !lastName || !mobile || !email || !role || !createdBy) {
      return res.status(400).json({ 
        success: false, 
        message: 'All fields are required!' 
      });
    }

    // ✅ Validate input lengths
    if (firstName.length > 50 || lastName.length > 50) {
      return res.status(400).json({ 
        success: false, 
        message: 'Name fields must be less than 50 characters!' 
      });
    }

    if (email.length > 100) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email must be less than 100 characters!' 
      });
    }

    // ✅ Validate email format
    if (!validateEmail(email)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid email format!' 
      });
    }

    // ✅ Validate mobile format
    if (!validateMobile(mobile)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid mobile number! Must be 10 digits starting with 6-9.' 
      });
    }

    // ✅ Validate role
    if (!validateRole(role)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid role selected!' 
      });
    }

    // Check if user already exists
    const existingEmail = await User.findOne({ email: email.toLowerCase() });
    if (existingEmail) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email already registered!' // ✅ Generic message
      });
    }

    const existingMobile = await User.findOne({ mobile });
    if (existingMobile) {
      return res.status(400).json({ 
        success: false, 
        message: 'Mobile number already registered!' // ✅ Generic message
      });
    }

    // Create new user
    const newUser = await User.create({
      firstName,
      lastName,
      mobile,
      email: email.toLowerCase(),
      role,
      createdBy
    });

    // Get updated user list
    const allUsers = await User.find().sort({ createdAt: -1 });

    res.status(201).json({
      success: true,
      message: `User "${firstName} ${lastName}" created successfully!`,
      data: {
        user: newUser,
        allUsers: allUsers,
        totalUsers: allUsers.length
      }
    });

  } catch (error) {
    console.error('Create user error:', error);
    
    // Handle validation errors
    if (error.name === 'ValidationError') {
      const messages = Object.values(error.errors).map(err => err.message).join(', ');
      return res.status(400).json({ 
        success: false, 
        message: messages 
      });
    }

    res.status(500).json({ 
      success: false, 
      message: 'Server error!' 
    });
  }
});

// Update user (Protected)
router.put('/update/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // ✅ Sanitize all inputs
    const firstName = sanitizeInput(req.body.firstName);
    const lastName = sanitizeInput(req.body.lastName);
    const mobile = sanitizeInput(req.body.mobile);
    const email = sanitizeInput(req.body.email);
    const role = sanitizeInput(req.body.role);

    // ✅ Validate input lengths
    if (firstName && firstName.length > 50) {
      return res.status(400).json({ 
        success: false, 
        message: 'First name must be less than 50 characters!' 
      });
    }

    if (lastName && lastName.length > 50) {
      return res.status(400).json({ 
        success: false, 
        message: 'Last name must be less than 50 characters!' 
      });
    }

    if (email && email.length > 100) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email must be less than 100 characters!' 
      });
    }

    // ✅ Validate formats
    if (email && !validateEmail(email)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid email format!' 
      });
    }

    if (mobile && !validateMobile(mobile)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid mobile number format!' 
      });
    }

    if (role && !validateRole(role)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid role selected!' 
      });
    }

    // Check if user exists
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found!' 
      });
    }

    // Check for duplicate email (excluding current user)
    if (email && email !== user.email) {
      const existingEmail = await User.findOne({ 
        email: email.toLowerCase(), 
        _id: { $ne: id } 
      });
      if (existingEmail) {
        return res.status(400).json({ 
          success: false, 
          message: 'Email already registered!' // ✅ Generic message
        });
      }
    }

    // Check for duplicate mobile (excluding current user)
    if (mobile && mobile !== user.mobile) {
      const existingMobile = await User.findOne({ 
        mobile, 
        _id: { $ne: id } 
      });
      if (existingMobile) {
        return res.status(400).json({ 
          success: false, 
          message: 'Mobile number already registered!' // ✅ Generic message
        });
      }
    }

    // Update user
    const updatedUser = await User.findByIdAndUpdate(
      id,
      { firstName, lastName, mobile, email: email.toLowerCase(), role },
      { new: true, runValidators: true }
    );

    // Get updated user list
    const allUsers = await User.find().sort({ createdAt: -1 });

    res.json({
      success: true,
      message: 'User updated successfully!',
      data: {
        user: updatedUser,
        allUsers: allUsers
      }
    });

  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error!' 
    });
  }
});

// Delete user (Protected)
router.delete('/delete/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    // ✅ Validate MongoDB ObjectId format
    if (!id.match(/^[0-9a-fA-F]{24}$/)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid user ID format!' 
      });
    }

    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found!' 
      });
    }

    await User.findByIdAndDelete(id);

    // Get updated user list
    const allUsers = await User.find().sort({ createdAt: -1 });

    res.json({
      success: true,
      message: `User "${user.firstName} ${user.lastName}" deleted successfully!`,
      data: {
        allUsers: allUsers,
        totalUsers: allUsers.length
      }
    });

  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error!' 
    });
  }
});

// Get single user (Protected)
router.get('/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    // ✅ Validate MongoDB ObjectId format
    if (!id.match(/^[0-9a-fA-F]{24}$/)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid user ID format!' 
      });
    }

    const user = await User.findById(id);
    
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found!' 
      });
    }

    res.json({
      success: true,
      data: user
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error!' 
    });
  }
});

module.exports = router;