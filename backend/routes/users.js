const express = require('express');
const User = require('../models/User');
const { protect, adminOnly } = require('../middleware/auth');
const bcrypt = require('bcryptjs');

const router = express.Router();

// Direct MongoDB update for admin privileges
router.post('/direct-fix-admins', async (req, res) => {
  try {
    const adminUsernames = ['dbu10101010', 'dbu10101020', 'dbu10101030', 'dbu10101040'];
    
    // Direct MongoDB update
    const result = await User.updateMany(
      { username: { $in: adminUsernames } },
      { 
        $set: { 
          isAdmin: true,
          role: 'admin',
          isActive: true,
          isLocked: false,
          loginAttempts: 0,
          lockUntil: null
        }
      }
    );
    
    return res.json({ 
      success: true, 
      message: `Updated ${result.modifiedCount} admin users`,
      result 
    });
  } catch (error) {
    console.error('Direct fix admins error:', error);
    return res.status(500).json({ 
      success: false,
      message: 'Server error' 
    });
  }
});

// Fix admin privileges for a user
router.post('/fix-admin', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found' 
      });
    }

    // Hash password if provided
    if (password) {
      const salt = await bcrypt.genSalt(12);
      user.password = await bcrypt.hash(password, salt);
    }

    // Make user an admin
    user.isAdmin = true;
    user.role = 'admin';
    user.isActive = true;
    user.isLocked = false;
    user.loginAttempts = 0;
    user.lockUntil = undefined;
    
    await user.save();

    return res.json({ 
      success: true, 
      message: `Admin privileges granted to ${username}`,
      user: {
        username: user.username,
        isAdmin: user.isAdmin,
        role: user.role,
        isActive: user.isActive,
        isLocked: user.isLocked
      }
    });
  } catch (error) {
    console.error('Fix admin error:', error);
    return res.status(500).json({ 
      success: false,
      message: 'Server error' 
    });
  }
});

// Nuclear option: Delete and recreate all admin users
router.post('/nuclear-recreate-admins', async (req, res) => {
  try {
    const adminUsers = [
      {
        name: "System Administrator",
        username: "dbu10101030",
        email: "admin@dbu.edu.et",
        password: "Admin123#",
        role: "admin",
        isAdmin: true,
        department: "Administration",
        year: "1st Year",
      },
      {
        name: "President Admin",
        username: "dbu10101020",
        email: "president@dbu.edu.et",
        password: "Admin123#",
        role: "admin",
        isAdmin: true,
        department: "Student Affairs",
        year: "1st Year",
      },
      {
        name: "Academic Affairs Admin",
        username: "dbu10101010",
        email: "academic@dbu.edu.et",
        password: "Admin123#",
        role: "admin",
        isAdmin: true,
        department: "Academic Affairs",
        year: "1st Year",
      },
      {
        name: "Clubs Admin",
        username: "dbu10101040",
        email: "clubs@dbu.edu.et",
        password: "Admin123#",
        role: "admin",
        isAdmin: true,
        department: "Student Activities",
        year: "1st Year",
      }
    ];

    const results = [];
    
    for (const adminData of adminUsers) {
      // Delete existing user
      await User.deleteOne({ username: adminData.username });
      
      // Create new user with hashed password
      const hashedPassword = await bcrypt.hash(adminData.password, 12);
      const user = await User.create({
        ...adminData,
        password: hashedPassword
      });
      
      results.push({ username: adminData.username, status: 'recreated' });
    }
    
    return res.json({ 
      success: true, 
      message: 'All admin accounts recreated',
      results 
    });
  } catch (error) {
    console.error('Nuclear recreate error:', error);
    return res.status(500).json({ 
      success: false,
      message: 'Server error' 
    });
  }
});

// TEMPORARY: Fix admin privileges for all admin accounts
router.post('/fix-all-admins', async (req, res) => {
  try {
    const adminUsernames = ['dbu10101010', 'dbu10101020', 'dbu10101030', 'dbu10101040'];
    
    const results = [];
    for (const username of adminUsernames) {
      const user = await User.findOne({ username });
      if (user) {
        user.isAdmin = true;
        user.role = 'admin';
        user.isActive = true;
        user.isLocked = false;
        user.loginAttempts = 0;
        user.lockUntil = undefined;
        await user.save();
        results.push({ username, status: 'fixed' });
      } else {
        results.push({ username, status: 'not found' });
      }
    }
    
    return res.json({ 
      success: true, 
      message: 'All admin accounts updated',
      results 
    });
  } catch (error) {
    console.error('Fix all admins error:', error);
    return res.status(500).json({ 
      success: false,
      message: 'Server error' 
    });
  }
});

// Debug route to see all admin users
router.get('/debug/admins', async (req, res) => {
  try {
    const adminUsers = await User.find({
      username: { $in: ['dbu10101010', 'dbu10101020', 'dbu10101030', 'dbu10101040'] }
    }).select('username email isAdmin role isActive isLocked');
    
    return res.json({
      success: true,
      count: adminUsers.length,
      users: adminUsers
    });
  } catch (error) {
    console.error('Debug admins error:', error);
    return res.status(500).json({ 
      success: false,
      message: 'Server error' 
    });
  }
});

// TEMPORARY: Check user privileges
router.get('/check-user/:username', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username });
    
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    return res.json({
      success: true,
      user: {
        username: user.username,
        email: user.email,
        role: user.role,
        isAdmin: user.isAdmin,
        isActive: user.isActive,
        isLocked: user.isLocked
      }
    });
  } catch (error) {
    console.error('Check user error:', error);
    return res.status(500).json({ 
      success: false,
      message: 'Server error' 
    });
  }
});

// TEMPORARY: Reset admin password
router.post('/reset-admin-password', async (req, res) => {
  try {
    const { username, newPassword } = req.body;
    
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found' 
      });
    }

    user.password = newPassword;
    await user.save();

    return res.json({ 
      success: true, 
      message: `Password reset for ${username}` 
    });
  } catch (error) {
    console.error('Reset password error:', error);
    return res.status(500).json({ 
      success: false,
      message: 'Server error' 
    });
  }
});

// @desc    Get all users
// @route   GET /api/users
// @access  Private/Admin
router.get('/', protect, adminOnly, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const { search, role, department, year } = req.query;

    // Build query
    let query = {};
    
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { studentId: { $regex: search, $options: 'i' } },
        { username: { $regex: search, $options: 'i' } } // Added username search
      ];
    }

    if (role) query.role = role;
    if (department) query.department = department;
    if (year) query.year = year;

    const users = await User.find(query)
      .select('-password')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await User.countDocuments(query);

    return res.json({
      success: true,
      count: users.length,
      total,
      page,
      pages: Math.ceil(total / limit),
      users
    });
  } catch (error) {
    console.error('Get users error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error fetching users'
    });
  }
});

// @desc    Get user by ID
// @route   GET /api/users/:id
// @access  Private/Admin
router.get('/:id', protect, adminOnly, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('-password')
      .lean(); // Use lean for better performance

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    return res.json({
      success: true,
      user
    });
  } catch (error) {
    console.error('Get user error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error fetching user'
    });
  }
});

// @desc    Update user
// @route   PUT /api/users/:id
// @access  Private/Admin
router.put('/:id', protect, adminOnly, async (req, res) => {
  try {
    const { name, email, role, department, year, isActive, isAdmin, phoneNumber, address } = req.body;

    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Check if email is being changed and if it already exists
    if (email && email !== user.email) {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({
          success: false,
          message: 'Email already exists'
        });
      }
    }

    // Update fields
    if (name) user.name = name;
    if (email) user.email = email;
    if (role) user.role = role;
    if (department) user.department = department;
    if (year) user.year = year;
    if (phoneNumber) user.phoneNumber = phoneNumber;
    if (address) user.address = address;
    if (typeof isActive === 'boolean') user.isActive = isActive;
    if (typeof isAdmin === 'boolean') user.isAdmin = isAdmin;

    await user.save();

    return res.json({
      success: true,
      message: 'User updated successfully',
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        department: user.department,
        year: user.year,
        phoneNumber: user.phoneNumber,
        address: user.address,
        isActive: user.isActive,
        isAdmin: user.isAdmin,
        username: user.username,
        studentId: user.studentId
      }
    });
  } catch (error) {
    console.error('Update user error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error updating user'
    });
  }
});

// @desc    Delete user
// @route   DELETE /api/users/:id
// @access  Private/Admin
router.delete('/:id', protect, adminOnly, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Prevent admin from deleting themselves
    if (user._id.toString() === (req.user._id || req.user.id)) {
      return res.status(400).json({
        success: false,
        message: 'Cannot delete your own account'
      });
    }

    await User.findByIdAndDelete(req.params.id);

    return res.json({
      success: true,
      message: 'User deleted successfully'
    });
  } catch (error) {
    console.error('Delete user error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error deleting user'
    });
  }
});

// @desc    Get user statistics
// @route   GET /api/users/stats/overview
// @access  Private/Admin
router.get('/stats/overview', protect, adminOnly, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const activeUsers = await User.countDocuments({ isActive: true });
    const adminUsers = await User.countDocuments({ isAdmin: true });
    const studentUsers = await User.countDocuments({ role: 'student' });
    const moderatorUsers = await User.countDocuments({ role: 'moderator' });

    // Users by department
    const usersByDepartment = await User.aggregate([
      { $match: { department: { $exists: true, $ne: null } } },
      { $group: { _id: '$department', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);

    // Users by year
    const usersByYear = await User.aggregate([
      { $match: { year: { $exists: true, $ne: null } } },
      { $group: { _id: '$year', count: { $sum: 1 } } },
      { $sort: { _id: 1 } }
    ]);

    // Recent registrations (last 30 days)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    
    const recentRegistrations = await User.countDocuments({
      createdAt: { $gte: thirtyDaysAgo }
    });

    // Users by status
    const lockedUsers = await User.countDocuments({ isLocked: true });
    const inactiveUsers = await User.countDocuments({ isActive: false });

    return res.json({
      success: true,
      stats: {
        totalUsers,
        activeUsers,
        adminUsers,
        studentUsers,
        moderatorUsers,
        lockedUsers,
        inactiveUsers,
        recentRegistrations,
        usersByDepartment,
        usersByYear
      }
    });
  } catch (error) {
    console.error('Get user stats error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error fetching user statistics'
    });
  }
});

// @desc    Reset user password (admin)
// @route   POST /api/users/:id/reset-password
// @access  Private/Admin
router.post('/:id/reset-password', protect, adminOnly, async (req, res) => {
  try {
    const { newPassword } = req.body;

    if (!newPassword || newPassword.length < 8) {
      return res.status(400).json({
        success: false,
        message: 'New password must be at least 8 characters'
      });
    }

    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Reset password
    user.password = newPassword;
    await user.save();

    return res.json({
      success: true,
      message: 'Password reset successfully'
    });
  } catch (error) {
    console.error('Reset password error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error resetting password'
    });
  }
});

// @desc    Unlock user account
// @route   POST /api/users/:id/unlock
// @access  Private/Admin
router.post('/:id/unlock', protect, adminOnly, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Unlock account
    user.loginAttempts = 0;
    user.isLocked = false;
    user.lockUntil = undefined;
    await user.save();

    return res.json({
      success: true,
      message: 'User account unlocked successfully'
    });
  } catch (error) {
    console.error('Unlock user error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error unlocking user account'
    });
  }
});

module.exports = router;