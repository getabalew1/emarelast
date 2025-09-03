/** @format */

const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const User = require("../models/User");
const { protect } = require("../middleware/auth");
const {
	validateUserRegistration,
	validateUserLogin,
} = require("../middleware/validation");

const router = express.Router();

// Generate JWT Token
const generateToken = (id) => {
	return jwt.sign({ id }, process.env.JWT_SECRET, {
		expiresIn: process.env.JWT_EXPIRE || "7d",
	});
};

// @desc    Register user
// @route   POST /api/auth/register
// @access  Public
router.post("/register", validateUserRegistration, async (req, res) => {
	try {
		const { name, username, password, department, year, phoneNumber, email } =
			req.body;

		console.log('Registration attempt:', { username, email });

		// Check if user exists
		const userExists = await User.findOne({
			$or: [{ username: username }, ...(email ? [{ email: email }] : [])],
		});

		if (userExists) {
			return res.status(400).json({
				success: false,
				message: "User already exists with this username or email",
			});
		}

		// Create user
		const user = await User.create({
			name,
			username,
			password,
			department,
			year,
			phoneNumber,
			email: email || undefined,
			studentId: username,
		});

		// Generate token
		const token = generateToken(user._id);

		console.log('Registration successful:', username);
		return res.status(201).json({
			success: true,
			message: "User registered successfully",
			token,
			user: {
				id: user._id,
				name: user.name,
				username: user.username,
				email: user.email,
				department: user.department,
				year: user.year,
				role: user.role,
				isAdmin: user.isAdmin,
				profileImage: user.profileImage,
			},
		});
	} catch (error) {
		console.error("Registration error:", error);

		if (error.name === "ValidationError") {
			const errors = Object.values(error.errors).map((err) => err.message);
			return res.status(400).json({
				success: false,
				message: "Validation failed",
				errors,
			});
		}

		return res.status(500).json({
			success: false,
			message: "Server error during registration",
		});
	}
});

// @desc    Login user (Student)
// @route   POST /api/auth/login
// @access  Public
router.post("/login", validateUserLogin, async (req, res) => {
	try {
		const { username, password } = req.body;

		console.log('Login attempt:', username);

		// Check for user and include password
		const user = await User.findOne({ username }).select("+password");
		if (!user) {
			console.log('User not found:', username);
			return res.status(401).json({
				success: false,
				message: "Invalid credentials",
			});
		}

		console.log('User found:', user.username, 'Active:', user.isActive, 'Locked:', user.isLocked);

		// Check if account is locked
		if (user.isLocked && user.lockUntil > Date.now()) {
			console.log('Account locked:', username);
			return res.status(423).json({
				success: false,
				message: "Account temporarily locked due to too many failed login attempts",
			});
		}

		// Reset lock if expired
		if (user.isLocked && user.lockUntil <= Date.now()) {
			user.loginAttempts = 0;
			user.isLocked = false;
			user.lockUntil = undefined;
			await user.save();
			console.log('Lock reset for:', username);
		}

		// Check if user is active
		if (!user.isActive) {
			console.log('Account inactive:', username);
			return res.status(401).json({
				success: false,
				message: "Account has been deactivated",
			});
		}

		// Check password
		const isMatch = await bcrypt.compare(password, user.password);
		console.log('Password match result:', isMatch);

		if (!isMatch) {
			console.log('Password mismatch for:', username);
			
			// Increment login attempts
			user.loginAttempts = (user.loginAttempts || 0) + 1;
			if (user.loginAttempts >= 5) {
				user.isLocked = true;
				user.lockUntil = Date.now() + 30 * 60 * 1000;
			}
			await user.save();
			
			return res.status(401).json({
				success: false,
				message: "Invalid credentials",
			});
		}

		// Reset login attempts on successful login
		user.loginAttempts = 0;
		user.isLocked = false;
		user.lockUntil = undefined;
		user.lastLogin = new Date();
		await user.save();

		// Generate token
		const token = generateToken(user._id);

		console.log('Login successful:', username);
		return res.json({
			success: true,
			message: "Login successful",
			token,
			user: {
				id: user._id,
				name: user.name,
				username: user.username,
				email: user.email,
				department: user.department,
				year: user.year,
				role: user.role || 'student',
				isAdmin: user.isAdmin,
				profileImage: user.profileImage,
			},
		});
	} catch (error) {
		console.error("Login error:", error);
		return res.status(500).json({
			success: false,
			message: "Server error during login",
		});
	}
});

// @desc    Admin Login
// @route   POST /api/auth/admin-login
// @access  Public
router.post("/admin-login", async (req, res) => {
  try {
    const { username, password } = req.body;

    console.log('Admin login attempt:', username);

    // Find user with password field
    const admin = await User.findOne({ username }).select("+password");
    if (!admin) {
      return res.status(401).json({ 
        success: false,
        message: "Admin account not found. Please contact system administrator." 
      });
    }

    // Check if user is actually an admin
    if (!admin.isAdmin && admin.role !== 'admin') {
      console.log('Admin privilege check failed:', {
        username: admin.username,
        isAdmin: admin.isAdmin,
        role: admin.role
      });
      return res.status(403).json({ 
        success: false,
        message: "Access denied. This account does not have admin privileges." 
      });
    }

    // Check if account is active
    if (!admin.isActive) {
      return res.status(403).json({ 
        success: false,
        message: "Account has been deactivated" 
      });
    }

    // Check if account is locked
    if (admin.isLocked && admin.lockUntil > Date.now()) {
      return res.status(423).json({ 
        success: false,
        message: "Account temporarily locked due to too many failed login attempts" 
      });
    }

    // Check password using bcrypt
    const isMatch = await bcrypt.compare(password, admin.password);
    console.log('Admin password match:', isMatch);
    
    if (!isMatch) {
      // Increment login attempts
      admin.loginAttempts += 1;
      if (admin.loginAttempts >= 5) {
        admin.isLocked = true;
        admin.lockUntil = Date.now() + 30 * 60 * 1000;
      }
      await admin.save();

      return res.status(401).json({ 
        success: false,
        message: "Invalid credentials. Please check your username and password." 
      });
    }

    // Reset login attempts on successful login
    admin.loginAttempts = 0;
    admin.isLocked = false;
    admin.lockUntil = undefined;
    admin.lastLogin = new Date();
    await admin.save();

    // Generate token with admin role
    const token = jwt.sign(
      { 
        id: admin._id, 
        role: 'admin',
        isAdmin: true 
      }, 
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    console.log('Admin login successful:', username);
    
    return res.status(200).json({ 
      success: true,
      message: "Admin login successful",
      token,
      user: {
        id: admin._id,
        name: admin.name,
        username: admin.username,
        email: admin.email,
        role: admin.role,
        isAdmin: admin.isAdmin,
        profileImage: admin.profileImage
      }
    });

  } catch (error) {
    console.error("Admin login error:", error);
    return res.status(500).json({ 
      success: false,
      message: "Internal server error" 
    });
  }
});

// @desc    Get current user profile
// @route   GET /api/auth/profile
// @access  Private
router.get("/profile", protect, async (req, res) => {
	try {
		const user = await User.findById(req.user.id).select("-password");

		return res.json({
			success: true,
			user,
		});
	} catch (error) {
		console.error("Profile fetch error:", error);
		return res.status(500).json({
			success: false,
			message: "Server error fetching profile",
		});
	}
});

// @desc    Update user profile
// @route   PUT /api/auth/profile
// @access  Private
router.put("/profile", protect, async (req, res) => {
	try {
		const { name, department, year, phoneNumber, address, email } = req.body;

		const user = await User.findById(req.user.id);
		if (!user) {
			return res.status(404).json({
				success: false,
				message: "User not found",
			});
		}

		// Update fields
		if (name) user.name = name;
		if (department) user.department = department;
		if (year) user.year = year;
		if (phoneNumber) user.phoneNumber = phoneNumber;
		if (address) user.address = address;
		if (email) user.email = email;

		await user.save();

		return res.json({
			success: true,
			message: "Profile updated successfully",
			user: {
				id: user._id,
				name: user.name,
				email: user.email,
				username: user.username,
				department: user.department,
				year: user.year,
				phoneNumber: user.phoneNumber,
				address: user.address,
				role: user.role,
				isAdmin: user.isAdmin,
				profileImage: user.profileImage,
			},
		});
	} catch (error) {
		console.error("Profile update error:", error);
		return res.status(500).json({
			success: false,
			message: "Server error updating profile",
		});
	}
});

// @desc    Change password
// @route   PUT /api/auth/change-password
// @access  Private
router.put("/change-password", protect, async (req, res) => {
	try {
		const { currentPassword, newPassword } = req.body;

		if (!currentPassword || !newPassword) {
			return res.status(400).json({
				success: false,
				message: "Please provide current and new password",
			});
		}

		if (newPassword.length < 8) {
			return res.status(400).json({
				success: false,
				message: "New password must be at least 8 characters",
			});
		}

		const user = await User.findById(req.user.id).select("+password");

		// Check current password
		const isMatch = await bcrypt.compare(currentPassword, user.password);
		if (!isMatch) {
			return res.status(400).json({
				success: false,
				message: "Current password is incorrect",
			});
		}

		// Update password
		user.password = newPassword;
		await user.save();

		return res.json({
			success: true,
			message: "Password changed successfully",
		});
	} catch (error) {
		console.error("Password change error:", error);
		return res.status(500).json({
			success: false,
			message: "Server error changing password",
		});
	}
});

// @desc    Logout user (client-side token removal)
// @route   POST /api/auth/logout
// @access  Private
router.post("/logout", protect, (req, res) => {
	return res.json({
		success: true,
		message: "Logged out successfully",
	});
});

module.exports = router;