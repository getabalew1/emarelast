const express = require('express');
const Post = require('../models/Post');
const { protect, adminOnly, optionalAuth } = require('../middleware/auth');
const { validatePost } = require('../middleware/validation');

const router = express.Router();

// @desc    Get all posts
// @route   GET /api/posts
// @access  Public
router.get('/', optionalAuth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const { type, category, status, search, important } = req.query;

    // Build query
    let query = {};
    
    // Only show published posts to non-admin users
    if (!req.user || !req.user.isAdmin) {
      query.status = 'published';
    } else if (status) {
      query.status = status;
    }

    if (type) query.type = type;
    if (category) query.category = category;
    if (important === 'true') query.important = true;
    
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { content: { $regex: search, $options: 'i' } }
      ];
    }

    const posts = await Post.find(query)
      .populate('author', 'name email role')
      .populate('comments.user', 'name email')
      .populate('likes.user', 'name email')
      .sort({ isPinned: -1, date: -1 })
      .skip(skip)
      .limit(limit);

    const total = await Post.countDocuments(query);

    return res.json({
      success: true,
      count: posts.length,
      total,
      page,
      pages: Math.ceil(total / limit),
      posts,
      data: posts // Add data field for compatibility
    });
  } catch (error) {
    console.error('Get posts error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error fetching posts'
    });
  }
});

// @desc    Get single post
// @route   GET /api/posts/:id
// @access  Public
router.get('/:id', optionalAuth, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id)
      .populate('author', 'name email role')
      .populate('comments.user', 'name email')
      .populate('likes.user', 'name email')
      .populate('attendees', 'name email studentId');

    if (!post) {
      return res.status(404).json({
        success: false,
        message: 'Post not found'
      });
    }

    // Check if post is published for non-admin users
    if ((!req.user || !req.user.isAdmin) && post.status !== 'published') {
      return res.status(404).json({
        success: false,
        message: 'Post not found'
      });
    }

    // Increment views
    await post.incrementViews();

    return res.json({
      success: true,
      post
    });
  } catch (error) {
    console.error('Get post error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error fetching post'
    });
  }
});

// @desc    Create new post
// @route   POST /api/posts
// @access  Private/Admin
router.post('/', protect, adminOnly, validatePost, async (req, res) => {
  try {
    const { 
      title, 
      content, 
      type, 
      category, 
      date, 
      image, 
      location, 
      time, 
      eventDate,
      important, 
      expiryDate, 
      targetAudience,
      tags,
      isPinned,
      scheduledFor
    } = req.body;

    console.log('Received post data:', req.body);
    console.log('User creating post:', req.user);
    const postData = {
      title,
      content,
      type,
      category: category || 'General',
      date: date ? new Date(date) : new Date(),
      author: req.user._id || req.user.id,
      image,
      tags: tags || []
    };

    // Event specific fields
    if (type === 'Event') {
      postData.location = location;
      postData.time = time;
      if (eventDate) postData.eventDate = new Date(eventDate);
    }

    // Announcement specific fields
    if (type === 'Announcement') {
      postData.important = important || false;
      if (expiryDate) postData.expiryDate = new Date(expiryDate);
      postData.targetAudience = targetAudience || 'all';
    }

    // Admin only fields
    if (typeof isPinned === 'boolean') postData.isPinned = isPinned;
    if (scheduledFor) postData.scheduledFor = new Date(scheduledFor);

    console.log('Creating post with data:', postData);
    const post = await Post.create(postData);
    await post.populate('author', 'name email role');

    console.log('Post created successfully:', post);
    res.status(201).json({
      success: true,
      message: 'Post created successfully',
      post
    });
  } catch (error) {
    console.error('Create post error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error creating post',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @desc    Update post
// @route   PUT /api/posts/:id
// @access  Private/Admin
router.put('/:id', protect, adminOnly, async (req, res) => {
  try {
    const { 
      title, 
      content, 
      category, 
      image, 
      location, 
      time, 
      eventDate,
      important, 
      expiryDate, 
      targetAudience,
      tags,
      status,
      isPinned
    } = req.body;

    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({
        success: false,
        message: 'Post not found'
      });
    }

    // Update basic fields
    if (title) post.title = title;
    if (content) post.content = content;
    if (category) post.category = category;
    if (image) post.image = image;
    if (tags) post.tags = tags;
    if (status) post.status = status;
    if (typeof isPinned === 'boolean') post.isPinned = isPinned;

    // Event specific fields
    if (post.type === 'Event') {
      if (location) post.location = location;
      if (time) post.time = time;
      if (eventDate) post.eventDate = new Date(eventDate);
    }

    // Announcement specific fields
    if (post.type === 'Announcement') {
      if (typeof important === 'boolean') post.important = important;
      if (expiryDate) post.expiryDate = new Date(expiryDate);
      if (targetAudience) post.targetAudience = targetAudience;
    }

    await post.save();
    await post.populate('author', 'name email role');

    return res.json({
      success: true,
      message: 'Post updated successfully',
      post
    });
  } catch (error) {
    console.error('Update post error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error updating post'
    });
  }
});

// @desc    Delete post
// @route   DELETE /api/posts/:id
// @access  Private/Admin
router.delete('/:id', protect, adminOnly, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({
        success: false,
        message: 'Post not found'
      });
    }

    await Post.findByIdAndDelete(req.params.id);

    return res.json({
      success: true,
      message: 'Post deleted successfully'
    });
  } catch (error) {
    console.error('Delete post error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error deleting post'
    });
  }
});

// @desc    Like/Unlike post
// @route   POST /api/posts/:id/like
// @access  Private
router.post('/:id/like', protect, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({
        success: false,
        message: 'Post not found'
      });
    }

    const hasLiked = post.hasUserLiked(req.user.id);
    
    if (hasLiked) {
      // Unlike
      post.likes = post.likes.filter(like => like.user.toString() !== req.user.id);
    } else {
      // Like
      post.likes.push({ user: req.user.id });
    }

    await post.save();

    return res.json({
      success: true,
      message: hasLiked ? 'Post unliked' : 'Post liked',
      liked: !hasLiked,
      likeCount: post.likes.length
    });
  } catch (error) {
    console.error('Like post error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error liking post'
    });
  }
});

// @desc    Add comment to post
// @route   POST /api/posts/:id/comments
// @access  Private
router.post('/:id/comments', protect, async (req, res) => {
  try {
    const { content } = req.body;

    if (!content || content.trim().length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Comment content is required'
      });
    }

    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({
        success: false,
        message: 'Post not found'
      });
    }

    const comment = {
      user: req.user.id,
      content: content.trim()
    };

    post.comments.push(comment);
    await post.save();
    await post.populate('comments.user', 'name email');

    const newComment = post.comments[post.comments.length - 1];

    return res.json({
      success: true,
      message: 'Comment added successfully',
      comment: newComment
    });
  } catch (error) {
    console.error('Add comment error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error adding comment'
    });
  }
});

// @desc    Register for event
// @route   POST /api/posts/:id/register
// @access  Private
router.post('/:id/register', protect, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({
        success: false,
        message: 'Post not found'
      });
    }

    if (post.type !== 'Event') {
      return res.status(400).json({
        success: false,
        message: 'This is not an event post'
      });
    }

    // Check if user is already registered
    const isRegistered = post.attendees.includes(req.user.id);
    if (isRegistered) {
      return res.status(400).json({
        success: false,
        message: 'You are already registered for this event'
      });
    }

    // Check if event is full
    if (post.maxAttendees && post.attendees.length >= post.maxAttendees) {
      return res.status(400).json({
        success: false,
        message: 'Event is full'
      });
    }

    post.attendees.push(req.user.id);
    await post.save();

    return res.json({
      success: true,
      message: 'Successfully registered for event',
      attendeeCount: post.attendees.length
    });
  } catch (error) {
    console.error('Register for event error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error registering for event'
    });
  }
});

// @desc    Get post statistics
// @route   GET /api/posts/stats/overview
// @access  Private/Admin
router.get('/stats/overview', protect, adminOnly, async (req, res) => {
  try {
    const totalPosts = await Post.countDocuments();
    const publishedPosts = await Post.countDocuments({ status: 'published' });
    const draftPosts = await Post.countDocuments({ status: 'draft' });
    const pinnedPosts = await Post.countDocuments({ isPinned: true });

    // Posts by type
    const postsByType = await Post.aggregate([
      { $group: { _id: '$type', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);

    // Posts by category
    const postsByCategory = await Post.aggregate([
      { $group: { _id: '$category', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);

    // Total views and engagement
    const engagementStats = await Post.aggregate([
      { 
        $group: { 
          _id: null, 
          totalViews: { $sum: '$views' },
          totalLikes: { $sum: { $size: '$likes' } },
          totalComments: { $sum: { $size: '$comments' } }
        } 
      }
    ]);

    // Recent posts (last 30 days)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    
    const recentPosts = await Post.countDocuments({
      createdAt: { $gte: thirtyDaysAgo }
    });

    const popularPosts = await Post.find({ status: 'published' })
      .select('title views')
      .sort({ views: -1 })
      .limit(5);

    return res.json({
      success: true,
      stats: {
        totalPosts,
        publishedPosts,
        draftPosts,
        pinnedPosts,
        recentPosts,
        totalViews: engagementStats[0]?.totalViews || 0,
        totalLikes: engagementStats[0]?.totalLikes || 0,
        totalComments: engagementStats[0]?.totalComments || 0,
        postsByType,
        postsByCategory,
        popularPosts
      }
    });
  } catch (error) {
    console.error('Get post stats error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error fetching post statistics'
    });
  }
});

module.exports = router;