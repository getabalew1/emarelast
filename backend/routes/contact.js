const express = require('express');
const Contact = require('../models/Contact');
const { protect, adminOnly } = require('../middleware/auth');
const { validateContact } = require('../middleware/validation');

const router = express.Router();

// @desc    Submit contact message
// @route   POST /api/contact
// @access  Public
router.post('/', validateContact, async (req, res) => {
  try {
    const { name, email, subject, message, category } = req.body;

    const contact = await Contact.create({
      name,
      email,
      subject,
      message,
      category: category || 'general',
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.status(201).json({
      success: true,
      message: 'Your message has been sent successfully. We will get back to you soon.',
      contact: {
        id: contact._id,
        name: contact.name,
        email: contact.email,
        subject: contact.subject,
        category: contact.category,
        createdAt: contact.createdAt
      }
    });
  } catch (error) {
    console.error('Submit contact error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error submitting contact message'
    });
  }
});

// @desc    Get all contact messages
// @route   GET /api/contact
// @access  Private/Admin
router.get('/', protect, adminOnly, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const { status, category, priority, search } = req.query;

    // Build query
    let query = {};
    
    if (status) query.status = status;
    if (category) query.category = category;
    if (priority) query.priority = priority;
    
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { subject: { $regex: search, $options: 'i' } },
        { message: { $regex: search, $options: 'i' } }
      ];
    }

    const contacts = await Contact.find(query)
      .populate('assignedTo', 'name email role')
      .populate('replies.author', 'name email role')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await Contact.countDocuments(query);

    res.json({
      success: true,
      count: contacts.length,
      total,
      page,
      pages: Math.ceil(total / limit),
      contacts
    });
  } catch (error) {
    console.error('Get contacts error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error fetching contact messages'
    });
  }
});

// @desc    Get single contact message
// @route   GET /api/contact/:id
// @access  Private/Admin
router.get('/:id', protect, adminOnly, async (req, res) => {
  try {
    const contact = await Contact.findById(req.params.id)
      .populate('assignedTo', 'name email role')
      .populate('replies.author', 'name email role');

    if (!contact) {
      return res.status(404).json({
        success: false,
        message: 'Contact message not found'
      });
    }

    // Mark as read if it's new
    if (contact.status === 'new') {
      contact.status = 'read';
      await contact.save();
    }

    res.json({
      success: true,
      contact
    });
  } catch (error) {
    console.error('Get contact error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error fetching contact message'
    });
  }
});

// @desc    Update contact message status
// @route   PATCH /api/contact/:id/status
// @access  Private/Admin
router.patch('/:id/status', protect, adminOnly, async (req, res) => {
  try {
    const { status, priority } = req.body;

    const contact = await Contact.findById(req.params.id);
    if (!contact) {
      return res.status(404).json({
        success: false,
        message: 'Contact message not found'
      });
    }

    if (status && ['new', 'read', 'replied', 'resolved'].includes(status)) {
      contact.status = status;
    }

    if (priority && ['low', 'medium', 'high'].includes(priority)) {
      contact.priority = priority;
    }

    await contact.save();

    res.json({
      success: true,
      message: 'Contact message updated successfully',
      contact
    });
  } catch (error) {
    console.error('Update contact status error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error updating contact message'
    });
  }
});

// @desc    Reply to contact message
// @route   POST /api/contact/:id/reply
// @access  Private/Admin
router.post('/:id/reply', protect, adminOnly, async (req, res) => {
  try {
    const { message } = req.body;

    if (!message || message.trim().length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Reply message is required'
      });
    }

    const contact = await Contact.findById(req.params.id);
    if (!contact) {
      return res.status(404).json({
        success: false,
        message: 'Contact message not found'
      });
    }

    const reply = {
      author: req.user.id,
      message: message.trim()
    };

    contact.replies.push(reply);
    contact.status = 'replied';
    contact.assignedTo = req.user.id;

    await contact.save();
    await contact.populate('replies.author', 'name email role');

    const newReply = contact.replies[contact.replies.length - 1];

    res.json({
      success: true,
      message: 'Reply sent successfully',
      reply: newReply
    });
  } catch (error) {
    console.error('Reply to contact error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error sending reply'
    });
  }
});

// @desc    Assign contact message
// @route   PATCH /api/contact/:id/assign
// @access  Private/Admin
router.patch('/:id/assign', protect, adminOnly, async (req, res) => {
  try {
    const { assignedTo } = req.body;

    const contact = await Contact.findById(req.params.id);
    if (!contact) {
      return res.status(404).json({
        success: false,
        message: 'Contact message not found'
      });
    }

    // Verify assigned user exists and is admin
    const User = require('../models/User');
    const assignedUser = await User.findById(assignedTo);
    if (!assignedUser || !assignedUser.isAdmin) {
      return res.status(400).json({
        success: false,
        message: 'Invalid user assignment'
      });
    }

    contact.assignedTo = assignedTo;
    if (contact.status === 'new') {
      contact.status = 'read';
    }

    await contact.save();
    await contact.populate('assignedTo', 'name email role');

    res.json({
      success: true,
      message: 'Contact message assigned successfully',
      contact
    });
  } catch (error) {
    console.error('Assign contact error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error assigning contact message'
    });
  }
});

// @desc    Delete contact message
// @route   DELETE /api/contact/:id
// @access  Private/Admin
router.delete('/:id', protect, adminOnly, async (req, res) => {
  try {
    const contact = await Contact.findById(req.params.id);
    if (!contact) {
      return res.status(404).json({
        success: false,
        message: 'Contact message not found'
      });
    }

    await Contact.findByIdAndDelete(req.params.id);

    res.json({
      success: true,
      message: 'Contact message deleted successfully'
    });
  } catch (error) {
    console.error('Delete contact error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error deleting contact message'
    });
  }
});

// @desc    Get contact statistics
// @route   GET /api/contact/stats/overview
// @access  Private/Admin
router.get('/stats/overview', protect, adminOnly, async (req, res) => {
  try {
    const totalMessages = await Contact.countDocuments();
    const newMessages = await Contact.countDocuments({ status: 'new' });
    const readMessages = await Contact.countDocuments({ status: 'read' });
    const repliedMessages = await Contact.countDocuments({ status: 'replied' });
    const resolvedMessages = await Contact.countDocuments({ status: 'resolved' });

    // Messages by category
    const messagesByCategory = await Contact.aggregate([
      { $group: { _id: '$category', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);

    // Messages by priority
    const messagesByPriority = await Contact.aggregate([
      { $group: { _id: '$priority', count: { $sum: 1 } } }
    ]);

    // Recent messages (last 30 days)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    
    const recentMessages = await Contact.countDocuments({
      createdAt: { $gte: thirtyDaysAgo }
    });

    // Average response time for replied messages
    const repliedMessagesWithTime = await Contact.find({
      status: 'replied',
      'replies.0': { $exists: true }
    }).select('createdAt replies');

    let avgResponseTime = 0;
    if (repliedMessagesWithTime.length > 0) {
      const totalTime = repliedMessagesWithTime.reduce((sum, contact) => {
        const firstReply = contact.replies[0];
        return sum + (firstReply.sentAt - contact.createdAt);
      }, 0);
      avgResponseTime = Math.round(totalTime / repliedMessagesWithTime.length / (1000 * 60 * 60)); // in hours
    }

    res.json({
      success: true,
      stats: {
        totalMessages,
        newMessages,
        readMessages,
        repliedMessages,
        resolvedMessages,
        recentMessages,
        avgResponseTime,
        messagesByCategory,
        messagesByPriority
      }
    });
  } catch (error) {
    console.error('Get contact stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error fetching contact statistics'
    });
  }
});

module.exports = router;