const mongoose = require('mongoose');

const candidateSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  username: {
    type: String,
    required: true
  },
  department: {
    type: String,
    required: true,
    trim: true
  },
  year: {
    type: String,
    required: true
  },
  academicYear: {
    type: String,
    required: [true, 'Academic year is required for candidates'],
    enum: ['1st Year', '2nd Year', '3rd Year', '4th Year', '5th Year']
  },
  position: {
    type: String,
    required: true,
    trim: true
  },
  profileImage: {
    type: String,
    default: 'https://images.pexels.com/photos/3763188/pexels-photo-3763188.jpeg?auto=compress&cs=tinysrgb&w=400'
  },
  platform: [String],
  biography: {
    type: String,
    trim: true,
    maxlength: [1000, 'Biography cannot be more than 1000 characters']
  },
  votes: {
    type: Number,
    default: 0
  },
  voters: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }]
});

const electionSchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, 'Please provide an election title'],
    trim: true,
    maxlength: [200, 'Title cannot be more than 200 characters']
  },
  description: {
    type: String,
    required: [true, 'Please provide an election description'],
    trim: true,
    maxlength: [1000, 'Description cannot be more than 1000 characters']
  },
  startDate: {
    type: Date,
    required: [true, 'Please provide a start date']
  },
  endDate: {
    type: Date,
    required: [true, 'Please provide an end date']
  },
  status: {
    type: String,
    enum: ['upcoming', 'active', 'completed', 'cancelled'],
    default: 'upcoming'
  },
  candidates: [candidateSchema],
  totalVotes: {
    type: Number,
    default: 0
  },
  eligibleVoters: {
    type: Number,
    default: 0
  },
  voters: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    candidate: {
      type: mongoose.Schema.Types.ObjectId,
      required: true
    },
    votedAt: {
      type: Date,
      default: Date.now
    },
    ipAddress: String
  }],
  electionType: {
    type: String,
    enum: ['president', 'vice_president', 'secretary', 'treasurer', 'branch_leader', 'general'],
    default: 'general'
  },
  rules: [{
    type: String,
    trim: true
  }],
  isPublic: {
    type: Boolean,
    default: true
  },
  resultsPublished: {
    type: Boolean,
    default: false
  },
  publishedAt: Date,
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  }
}, {
  timestamps: true
});

// Index for better query performance
electionSchema.index({ status: 1 });
electionSchema.index({ startDate: 1 });
electionSchema.index({ endDate: 1 });
electionSchema.index({ 'voters.user': 1 });

// Update status based on dates
electionSchema.pre('save', function(next) {
  const now = new Date();
  
  if (this.startDate > now) {
    this.status = 'upcoming';
  } else if (this.startDate <= now && this.endDate > now) {
    this.status = 'active';
  } else if (this.endDate <= now) {
    this.status = 'completed';
  }
  
  next();
});

// Virtual for turnout percentage
electionSchema.virtual('turnoutPercentage').get(function() {
  if (this.eligibleVoters === 0) return 0;
  return ((this.totalVotes / this.eligibleVoters) * 100).toFixed(2);
});

// Method to check if user has voted
electionSchema.methods.hasUserVoted = function(userId) {
  return this.voters.some(voter => voter.user.toString() === userId.toString());
};

// Method to get winner
electionSchema.methods.getWinner = function() {
  if (this.candidates.length === 0) return null;
  
  return this.candidates.reduce((winner, candidate) => {
    return candidate.votes > winner.votes ? candidate : winner;
  });
};

module.exports = mongoose.model('Election', electionSchema);