const mongoose = require('mongoose');

const eventSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    trim: true
  },
  date: {
    type: Date,
    required: true
  },
  location: {
    type: String,
    trim: true
  },
  attendees: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  status: {
    type: String,
    enum: ['planned', 'ongoing', 'completed', 'cancelled'],
    default: 'planned'
  }
}, {
  timestamps: true
});

const clubSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Please provide a club name'],
    trim: true,
    unique: true,
    maxlength: [100, 'Club name cannot be more than 100 characters']
  },
  description: {
    type: String,
    required: [true, 'Please provide a club description'],
    trim: true,
    maxlength: [1000, 'Description cannot be more than 1000 characters']
  },
  category: {
    type: String,
    required: [true, 'Please select a category'],
    enum: ['Academic', 'Sports', 'Cultural', 'Technology', 'Service', 'Arts', 'Religious', 'Professional']
  },
  founded: {
    type: String,
    required: true
  },
  image: {
    type: String,
    default: 'https://images.pexels.com/photos/3184291/pexels-photo-3184291.jpeg?auto=compress&cs=tinysrgb&w=400'
  },
  members: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    fullName: {
      type: String,
      required: true
    },
    department: {
      type: String,
      required: true
    },
    year: {
      type: String,
      required: true
    },
    background: {
      type: String,
      trim: true
    },
    role: {
      type: String,
      enum: ['member', 'officer', 'president', 'vice_president', 'secretary', 'treasurer'],
      default: 'member'
    },
    status: {
      type: String,
      enum: ['pending', 'approved', 'rejected'],
      default: 'pending'
    },
    joinedAt: {
      type: Date,
      default: Date.now
    }
  }],
  leadership: {
    president: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    vicePresident: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    secretary: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    treasurer: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }
  },
  events: [eventSchema],
  status: {
    type: String,
    enum: ['active', 'inactive', 'pending_approval', 'suspended'],
    default: 'pending_approval'
  },
  contactEmail: {
    type: String,
    lowercase: true,
    match: [
      /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/,
      'Please provide a valid email'
    ]
  },
  officeLocation: {
    type: String,
    trim: true
  },
  contactPhone: {
    type: String,
    trim: true
  },
  website: {
    type: String,
    trim: true
  },
  meetingSchedule: {
    type: String,
    trim: true
  },
  requirements: {
    type: String,
    trim: true
  },
  achievements: [{
    title: String,
    description: String,
    date: Date
  }],
  socialMedia: {
    facebook: String,
    instagram: String,
    twitter: String,
    telegram: String
  },
  budget: {
    allocated: {
      type: Number,
      default: 0
    },
    spent: {
      type: Number,
      default: 0
    },
    remaining: {
      type: Number,
      default: 0
    }
  }
}, {
  timestamps: true
});

// Index for better query performance
clubSchema.index({ name: 1 });
clubSchema.index({ category: 1 });
clubSchema.index({ status: 1 });
clubSchema.index({ 'members.user': 1 });

// Virtual for member count
clubSchema.virtual('memberCount').get(function() {
  return this.members.filter(member => member.status === 'approved').length;
});

// Virtual for event count
clubSchema.virtual('eventCount').get(function() {
  return this.events.length;
});

// Update budget remaining when spent changes
clubSchema.pre('save', function(next) {
  if (this.isModified('budget.spent') || this.isModified('budget.allocated')) {
    this.budget.remaining = this.budget.allocated - this.budget.spent;
  }
  next();
});

module.exports = mongoose.model('Club', clubSchema);