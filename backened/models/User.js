const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: true,
    trim: true
  },
  lastName: {
    type: String,
    required: true,
    trim: true
  },
  mobile: {
    type: String,
    required: true,
    unique: true,
    validate: {
      validator: function(v) {
        return /^[6-9][0-9]{9}$/.test(v);
      },
      message: 'Invalid Indian mobile number!'
    }
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    validate: {
      validator: function(v) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
      },
      message: 'Invalid email address!'
    }
  },
  role: {
    type: String,
    required: true,
    enum: ['Admin', 'User', 'Manager', 'Employee', 'Supervisor']
  },
  createdBy: {
    type: String,
    required: true
  },
  isActive: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true
});

// Add index for faster queries
userSchema.index({ email: 1, mobile: 1 });

module.exports = mongoose.model('User', userSchema);