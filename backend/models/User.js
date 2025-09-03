const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

// Define the User schema
const userSchema = new mongoose.Schema(
	{
		name: {
			type: String,
			required: [true, "Please provide your name"],
			trim: true,
			maxlength: [50, "Name cannot be more than 50 characters"],
		},
		username: {
			type: String,
			required: [true, "Please provide a username"],
			unique: true,
			trim: true,
			match: [
				/^dbu\d{8}$/i,
				"Username must start with dbu followed by 8 digits",
			],
		},
		email: {
			type: String,
			unique: true,
			sparse: true,
			trim: true,
			lowercase: true,
			match: [
				/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/,
				"Please provide a valid email",
			],
		},
		password: {
			type: String,
			required: [true, "Please provide a password"],
			minlength: [8, "Password must be at least 8 characters"],
			select: false,
		},
		isActive: {
			type: Boolean,
			default: true,
		},
		department: {
			type: String,
			required: [true, "Please provide your department"],
			trim: true,
		},
		year: {
			type: String,
			required: [true, "Please provide your academic year"],
			enum: ["1st Year", "2nd Year", "3rd Year", "4th Year", "5th Year"],
		},
		isAdmin: {
			type: Boolean,
			default: false, // Default value set to false, can be set to true for admin users
		},
		role: {
			type: String,
			enum: ["student", "admin"],
			default: "student",
		},
		isLocked: {
			type: Boolean,
			default: false,
		},
		loginAttempts: {
			type: Number,
			default: 0,
		},
		lockUntil: Date,
		lastLogin: Date,
		joinedClubs: [{
			type: mongoose.Schema.Types.ObjectId,
			ref: 'Club'
		}],
		votedElections: [{
			type: mongoose.Schema.Types.ObjectId,
			ref: 'Election'
		}],
		profileImage: {
			type: String,
			default: 'https://images.pexels.com/photos/3763188/pexels-photo-3763188.jpeg?auto=compress&cs=tinysrgb&w=400'
		},
		studentId: {
			type: String,
			sparse: true
		},
		phoneNumber: {
			type: String,
			trim: true
		},
		address: {
			type: String,
			trim: true
		}
	},
	{
		timestamps: true,
	}
);

// Pre-save middleware to hash password
userSchema.pre("save", async function (next) {
	if (!this.isModified("password")) return next();
	try {
		const salt = await bcrypt.genSalt(12);
		this.password = await bcrypt.hash(this.password, salt);
		next();
	} catch (error) {
		next(error);
	}
});

// Method to match password
userSchema.methods.matchPassword = async function (enteredPassword) {
	return await bcrypt.compare(enteredPassword, this.password);
};

// Create the User model
const User = mongoose.model("User", userSchema);

module.exports = User;