const mongoose = require('mongoose');

const postSchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, 'Please provide a post title'],
    trim: true,
    maxlength: [200, 'Title cannot be more than 200 characters']
  },
  content: {
    type: String,
    required: [true, 'Please provide post content'],
    trim: true,
    maxlength: [5000, 'Content cannot be more than 5000 characters']
  },
  type: {
    type: String,
    required: [true, 'Please specify post type'],
    enum: ['News', 'Event', 'Announcement'],
    default: 'News'
  },
  category: {
    type: String,
    enum: ['General', 'Campus', 'Academic', 'Sports', 'Research', 'Cultural'],
    default: 'General'
  },
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  date: {
    type: Date,
    required: true,
    default: Date.now
  },
  image: {
    type: String,
    default: null
  },
  images: [{
    url: String,
    caption: String,
    uploadDate: {
      type: Date,
      default: Date.now
    }
  }],
  // Event specific fields
  location: {
    type: String,
    trim: true
  },
  time: {
    type: String,
    trim: true
  },
  eventDate: Date,
  registrationRequired: {
    type: Boolean,
    default: false
  },
  maxAttendees: Number,
  attendees: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  // Announcement specific fields
  important: {
    type: Boolean,
    default: false
  },
  expiryDate: Date,
  targetAudience: {
    type: String,
    enum: ['all', 'students', 'faculty', 'staff', 'specific'],
    default: 'all'
  },
  specificAudience: [String],
  status: {
    type: String,
    enum: ['draft', 'published', 'archived'],
    default: 'published'
  },
  tags: [String],
  views: {
    type: Number,
    default: 0
  },
  likes: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    likedAt: {
      type: Date,
      default: Date.now
    }
  }],
  comments: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    content: {
      type: String,
      required: true,
      trim: true,
      maxlength: [500, 'Comment cannot be more than 500 characters']
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  }],
  isPinned: {
    type: Boolean,
    default: false
  },
  publishedAt: Date,
  scheduledFor: Date
}, {
  timestamps: true
});

// Index for better query performance
postSchema.index({ type: 1 });
postSchema.index({ category: 1 });
postSchema.index({ author: 1 });
postSchema.index({ date: -1 });
postSchema.index({ status: 1 });
postSchema.index({ important: 1 });

// Virtual for like count
postSchema.virtual('likeCount').get(function() {
  return this.likes.length;
});

// Virtual for comment count
postSchema.virtual('commentCount').get(function() {
  return this.comments.length;
});

// Virtual for attendee count
postSchema.virtual('attendeeCount').get(function() {
  return this.attendees.length;
});

// Method to check if user has liked the post
postSchema.methods.hasUserLiked = function(userId) {
  return this.likes.some(like => like.user.toString() === userId.toString());
};

// Method to increment views
postSchema.methods.incrementViews = function() {
  this.views += 1;
  return this.save();
};

// Set published date when status changes to published
postSchema.pre('save', function(next) {
  if (this.isModified('status') && this.status === 'published' && !this.publishedAt) {
    this.publishedAt = new Date();
  }
  next();
});

module.exports = mongoose.model('Post', postSchema);