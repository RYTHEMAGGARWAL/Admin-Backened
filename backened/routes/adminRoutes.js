const express = require('express');
const router = express.Router();
const ExcelJS = require('exceljs');
const Admin = require('../models/Admin');
const User = require('../models/User');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
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

// ✅ FIX 1: Create automatic backup before data deletion
const createBackup = async () => {
  try {
    const backupDir = path.join(__dirname, '../backups');
    
    // Create backups directory if not exists
    if (!fs.existsSync(backupDir)) {
      fs.mkdirSync(backupDir, { recursive: true });
    }

    const admins = await Admin.find();
    const users = await User.find();
    
    const backup = {
      timestamp: new Date().toISOString(),
      adminCount: admins.length,
      userCount: users.length,
      admins: admins.map(a => ({
        username: a.username,
        excelFileName: a.excelFileName,
        lastLogin: a.lastLogin,
        createdAt: a.createdAt
      })),
      users: users.map(u => ({
        firstName: u.firstName,
        lastName: u.lastName,
        mobile: u.mobile,
        email: u.email,
        role: u.role,
        createdBy: u.createdBy,
        createdAt: u.createdAt
      }))
    };

    const backupFileName = `backup_${Date.now()}.json`;
    const backupPath = path.join(backupDir, backupFileName);
    
    await fs.promises.writeFile(backupPath, JSON.stringify(backup, null, 2));
    
    console.log(`✅ Backup created: ${backupFileName}`);
    return backupFileName;
  } catch (error) {
    console.error('❌ Backup creation failed:', error);
    throw new Error('Failed to create backup!');
  }
};

// JWT Middleware for protected routes
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

// ✅ FIX 2: Add token refresh endpoint
router.post('/refresh-token', authenticateToken, async (req, res) => {
  try {
    // Generate new token with same user data
    const newToken = jwt.sign(
      { username: req.user.username, id: req.user.id },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    // Update last activity
    await Admin.findOneAndUpdate(
      { username: req.user.username },
      { lastLogin: new Date() }
    );

    res.json({
      success: true,
      message: 'Token refreshed successfully!',
      token: newToken
    });
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({ success: false, message: 'Failed to refresh token!' });
  }
});

// Separate Login Endpoint (without upload - for re-login)
router.post('/login-only', async (req, res) => {
  try {
    // ✅ Sanitize inputs
    const username = sanitizeInput(req.body.username);
    const password = sanitizeInput(req.body.password);

    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username and password required!' });
    }

    // ✅ Validate input length
    if (username.length > 50 || password.length > 100) {
      return res.status(400).json({ success: false, message: 'Invalid input length!' });
    }

    // Fetch existing admin from DB
    const admin = await Admin.findOne({ username });
    
    if (!admin) {
      return res.status(401).json({ success: false, message: 'Invalid credentials!' });
    }

    // Compare hashed password
    const isPasswordValid = await bcrypt.compare(password, admin.password);
    
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Invalid credentials!' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { username: admin.username, id: admin._id },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    // Update lastLogin
    await Admin.findByIdAndUpdate(admin._id, { lastLogin: new Date() });

    // Fetch users
    const allUsers = await User.find().sort({ createdAt: -1 });

    res.json({
      success: true,
      message: 'Login successful!',
      token: token,
      data: {
        username: admin.username,
        excelFileName: admin.excelFileName,
        totalUsers: allUsers.length,
        users: allUsers
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Server error!' });
  }
});

// Upload Excel and Login (with password hashing)
router.post('/upload-and-login', async (req, res) => {
  try {
    const upload = req.app.get('upload');
    
    upload.single('excelFile')(req, res, async (err) => {
      if (err) {
        console.error('Multer error:', err);
        return res.status(400).json({ 
          success: false, 
          message: err.message 
        });
      }

      if (!req.file) {
        return res.status(400).json({ 
          success: false, 
          message: 'Please upload Excel file!' 
        });
      }

      // ✅ Sanitize inputs
      const username = sanitizeInput(req.body.username);
      const password = sanitizeInput(req.body.password);

      if (!username || !password) {
        if (req.file && req.file.path) fs.unlinkSync(req.file.path);
        return res.status(400).json({ 
          success: false, 
          message: 'Username and password required!' 
        });
      }

      // ✅ Validate input length
      if (username.length > 50 || password.length > 100) {
        if (req.file && req.file.path) fs.unlinkSync(req.file.path);
        return res.status(400).json({ 
          success: false, 
          message: 'Invalid input length!' 
        });
      }

      try {
        // Read Excel file
        const workbook = new ExcelJS.Workbook();
        await workbook.xlsx.readFile(req.file.path);

        // Check for Admin sheet
        const adminSheet = workbook.getWorksheet('Admin');
        if (!adminSheet) {
          fs.unlinkSync(req.file.path);
          return res.status(400).json({ 
            success: false, 
            message: 'Admin sheet not found in Excel file!' 
          });
        }

        // Parse Admin sheet
       const adminData = [];
adminSheet.eachRow({ includeEmpty: false }, (row, rowNumber) => {
  if (rowNumber === 1) return;
  const userCell = row.getCell(1).value;
  const passCell = row.getCell(2).value;
  if (userCell && passCell) {
    adminData.push({
      username: sanitizeInput(userCell.toString().trim()),
      password: sanitizeInput(passCell.toString().trim())
    });
  }
});

if (adminData.length === 0) {
  fs.unlinkSync(req.file.path);
  return res.status(400).json({ 
    success: false, 
    message: 'Admin sheet is empty!' 
  });
}

// ✅ NEW: Validate placeholder passwords
const hasPlaceholder = adminData.some(admin => 
  admin.password === '[ENTER_NEW_PASSWORD_HERE]' || 
  admin.password.includes('ENTER') ||
  admin.password.includes('PASSWORD') ||
  admin.password.includes('HERE')
);

if (hasPlaceholder) {
  fs.unlinkSync(req.file.path);
  return res.status(400).json({ 
    success: false, 
    message: '❌ ERROR: Please replace ALL placeholder passwords in Admin sheet before uploading!' 
  });
}

// ✅ NEW: Validate password strength
const weakPasswords = adminData.filter(admin => admin.password.length < 8);
if (weakPasswords.length > 0) {
  fs.unlinkSync(req.file.path);
  return res.status(400).json({ 
    success: false, 
    message: `❌ ERROR: All passwords must be at least 8 characters! Found ${weakPasswords.length} weak password(s).` 
  });
}

        // Find matching admin credentials (plain text from Excel)
        const adminMatch = adminData.find(
          admin => admin.username === username && admin.password === password
        );

        if (!adminMatch) {
          fs.unlinkSync(req.file.path);
          return res.status(401).json({ 
            success: false, 
            message: 'Invalid credentials!' 
          });
        }

        // ✅ FIX 1: Create backup before deletion
        const existingAdmins = await Admin.countDocuments();
        const existingUsers = await User.countDocuments();
        
        let backupFileName = null;
        if (existingAdmins > 0 || existingUsers > 0) {
          console.log(`⚠️ REPLACING DATA: ${existingAdmins} admins and ${existingUsers} users`);
          backupFileName = await createBackup();
        }
        
        // Clear existing data
        await Admin.deleteMany({});
        
        // Hash passwords and save all admins from Excel
        const adminPromises = adminData.map(async admin => {
          const hashedPassword = await bcrypt.hash(admin.password, 10);
          return Admin.create({
            username: admin.username,
            password: hashedPassword,
            excelFileName: req.file.originalname,
            lastLogin: admin.username === username ? new Date() : undefined
          });
        });

        await Promise.all(adminPromises);

        // Parse Users sheet (if exists)
        let usersData = [];
        const usersSheet = workbook.getWorksheet('Users');
        if (usersSheet) {
          usersSheet.eachRow({ includeEmpty: false }, (row, rowNumber) => {
            if (rowNumber === 1) return;
            const cells = [
              row.getCell(1).value?.toString().trim(),
              row.getCell(2).value?.toString().trim(),
              row.getCell(3).value?.toString().trim(),
              row.getCell(4).value?.toString().trim(),
              row.getCell(5).value?.toString().trim(),
              row.getCell(6)?.value?.toString().trim()
            ];
            if (cells[0] && cells[1] && cells[2] && cells[3] && cells[4]) {
              // ✅ Sanitize all user inputs
              usersData.push({
                firstName: sanitizeInput(cells[0]),
                lastName: sanitizeInput(cells[1]),
                mobile: sanitizeInput(cells[2]),
                email: sanitizeInput(cells[3]).toLowerCase(),
                role: sanitizeInput(cells[4]),
                createdBy: sanitizeInput(cells[5] || username)
              });
            }
          });

          await User.deleteMany({});
          
          if (usersData.length > 0) {
            await User.insertMany(usersData);
          }
        }

        const allUsers = await User.find().sort({ createdAt: -1 });

        // Generate JWT token
        const token = jwt.sign(
          { username: username, id: adminMatch.username },
          process.env.JWT_SECRET,
          { expiresIn: '15m' }
        );

        // Cleanup uploaded file
        try {
          fs.unlinkSync(req.file.path);
        } catch (cleanupErr) {
          console.error('File cleanup error:', cleanupErr);
        }

        res.json({
          success: true,
          message: backupFileName 
            ? `Login successful! Backup saved: ${backupFileName}` 
            : 'Login successful!',
          token: token,
          data: {
            username: username,
            excelFileName: req.file.originalname,
            totalUsers: allUsers.length,
            users: allUsers,
            replacedData: { admins: existingAdmins, users: existingUsers },
            backupFile: backupFileName
          }
        });

      } catch (error) {
        console.error('Excel processing error:', error);
        try {
          if (req.file && req.file.path) fs.unlinkSync(req.file.path);
        } catch (cleanupErr) {
          console.error('File cleanup error:', cleanupErr);
        }
        res.status(500).json({ 
          success: false, 
          message: 'Failed to process Excel file!' 
        });
      }
    });

  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error!' 
    });
  }
});


// ✅ FIX 3: Improved Excel download with password instructions
router.get('/download-excel', authenticateToken, async (req, res) => {
  try {
    const admins = await Admin.find();
    const users = await User.find().sort({ createdAt: -1 });

    if (admins.length === 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'No admin data found!' 
      });
    }

    const workbook = new ExcelJS.Workbook();

    // ✅ Admin sheet with clear password instructions
    const adminSheet = workbook.addWorksheet('Admin');
    adminSheet.columns = [
      { header: 'username', key: 'username', width: 20 },
      { header: 'password', key: 'password', width: 40 }
    ];
    
    // Add BOLD instruction rows
    adminSheet.addRow({ 
      username: '⚠️ CRITICAL INSTRUCTION', 
      password: 'READ BEFORE RE-UPLOADING!' 
    });
    adminSheet.getRow(2).font = { bold: true, size: 12, color: { argb: 'FFFF0000' } };
    adminSheet.getRow(2).fill = {
      type: 'pattern',
      pattern: 'solid',
      fgColor: { argb: 'FFFFCCCC' }
    };
    
    adminSheet.addRow({ 
      username: '1. Replace ALL passwords below', 
      password: 'Use strong passwords (min 8 chars)' 
    });
    adminSheet.getRow(3).font = { bold: true, color: { argb: 'FFFF0000' } };
    
    adminSheet.addRow({ 
      username: '2. Current passwords are HASHED', 
      password: 'They will NOT work for login' 
    });
    adminSheet.getRow(4).font = { bold: true, color: { argb: 'FFFF0000' } };
    
    adminSheet.addRow({ 
      username: '3. Delete these 4 instruction rows', 
      password: 'Before uploading the file' 
    });
    adminSheet.getRow(5).font = { bold: true, color: { argb: 'FFFF0000' } };
    
    adminSheet.addRow({}); // Empty row for separation
    
    // ✅ Add admin data with placeholder passwords
    admins.forEach(admin => {
      adminSheet.addRow({
        username: admin.username,
        password: '[ENTER_NEW_PASSWORD_HERE]' // ✅ Placeholder password
      });
    });

    // Users sheet
    const usersSheet = workbook.addWorksheet('Users');
    usersSheet.columns = [
      { header: 'firstName', key: 'firstName', width: 15 },
      { header: 'lastName', key: 'lastName', width: 15 },
      { header: 'mobile', key: 'mobile', width: 12 },
      { header: 'email', key: 'email', width: 25 },
      { header: 'role', key: 'role', width: 12 },
      { header: 'createdBy', key: 'createdBy', width: 15 }
    ];
    users.forEach(user => {
      usersSheet.addRow({
        firstName: user.firstName,
        lastName: user.lastName,
        mobile: user.mobile,
        email: user.email,
        role: user.role,
        createdBy: user.createdBy
      });
    });

    const buffer = await workbook.xlsx.writeBuffer();
    const fileName = `users_backup_${Date.now()}.xlsx`;

    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.send(buffer);

  } catch (error) {
    console.error('Download error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to download Excel file!' 
    });
  }
});
// Get current session info (Protected)
router.get('/session', authenticateToken, async (req, res) => {
  try {
    const admin = await Admin.findOne({ username: req.user.username });
    const userCount = await User.countDocuments();

    if (!admin) {
      return res.status(404).json({ 
        success: false, 
        message: 'No active session found!' 
      });
    }

    res.json({
      success: true,
      data: {
        username: admin.username,
        excelFileName: admin.excelFileName,
        totalUsers: userCount,
        lastLogin: admin.lastLogin
      }
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Server error!' 
    });
  }
});

module.exports = router;