const express = require('express');
const Complaint = require('../models/Complaint');
const User = require('../models/User');
const { protect, adminOnly, authorize } = require('../middleware/auth');
const { validateComplaint } = require('../middleware/validation');

const router = express.Router();

// @desc    Get all complaints
// @route   GET /api/complaints
// @access  Private
router.get('/', protect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const { status, category, priority, search } = req.query;

    // Build query
    let query = {};
    
    // Non-admin users can only see their own complaints
    if (!req.user.isAdmin && !req.user.role === 'admin') {
      // For mock users, don't filter by submittedBy since they won't have real ObjectIds
      if (req.user.id && !req.user.id.toString().includes('admin_') && 
          !req.user.id.toString().includes('student_') && 
          !req.user.id.toString().includes('google_')) {
        query.submittedBy = req.user.id;
      }
    }

    if (status) query.status = status;
    if (category) query.category = category;
    if (priority) query.priority = priority;
    
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { caseId: { $regex: search, $options: 'i' } }
      ];
    }

    const complaints = await Complaint.find(query)
      .populate('submittedBy', 'name email studentId')
      .populate('assignedTo', 'name email role')
      .populate('responses.authorId', 'name role')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await Complaint.countDocuments(query);

    res.json({
      success: true,
      count: complaints.length,
      total,
      page,
      pages: Math.ceil(total / limit),
      complaints,
      data: complaints // Add data field for compatibility
    });
  } catch (error) {
    console.error('Get complaints error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error fetching complaints'
    });
  }
});

// @desc    Get single complaint
// @route   GET /api/complaints/:id
// @access  Private
router.get('/:id', protect, async (req, res) => {
  try {
    const complaint = await Complaint.findById(req.params.id)
      .populate('submittedBy', 'name email studentId')
      .populate('assignedTo', 'name email role')
      .populate('responses.authorId', 'name role');

    if (!complaint) {
      return res.status(404).json({
        success: false,
        message: 'Complaint not found'
      });
    }

    // Check if user can access this complaint
    if (!req.user.isAdmin && !req.user.role === 'admin' && complaint.submittedBy && complaint.submittedBy._id.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to access this complaint'
      });
    }

    res.json({
      success: true,
      complaint
    });
  } catch (error) {
    console.error('Get complaint error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error fetching complaint'
    });
  }
});

// @desc    Create new complaint
// @route   POST /api/complaints
// @access  Private
router.post('/', protect, validateComplaint, async (req, res) => {
  try {
    const { title, description, category, priority, branch } = req.body;

    const complaint = await Complaint.create({
      title,
      description,
      category,
      priority: priority || 'medium',
      branch: branch || category,
      submittedBy: req.user._id || req.user.id
    });

    await complaint.populate('submittedBy', 'name email studentId');

    return res.status(201).json({
      success: true,
      message: 'Complaint submitted successfully',
      complaint
    });
  } catch (error) {
    console.error('Create complaint error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error creating complaint'
    });
  }
});

// @desc    Update complaint status
// @route   PATCH /api/complaints/:id/status
// @access  Private/Admin
router.patch('/:id/status', protect, adminOnly, async (req, res) => {
  try {
    const { status } = req.body;

    if (!['submitted', 'under_review', 'resolved', 'closed'].includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid status'
      });
    }

    if (!req.params.id || req.params.id === 'undefined') {
      return res.status(400).json({
        success: false,
        message: 'Invalid complaint ID'
      });
    }

    const complaint = await Complaint.findById(req.params.id);
    if (!complaint) {
      return res.status(404).json({
        success: false,
        message: 'Complaint not found'
      });
    }

    complaint.status = status;
    if (status === 'under_review' && !complaint.assignedTo) {
      complaint.assignedTo = req.user.id;
    }

    await complaint.save();
    await complaint.populate('submittedBy', 'name email');
    await complaint.populate('assignedTo', 'name email role');

    res.json({
      success: true,
      message: 'Complaint status updated successfully',
      complaint
    });
  } catch (error) {
    console.error('Update complaint status error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error updating complaint status'
    });
  }
});

// @desc    Add response to complaint
// @route   POST /api/complaints/:id/responses
// @access  Private/Admin
router.post('/:id/responses', protect, adminOnly, async (req, res) => {
  try {
    const { message } = req.body;

    if (!message || message.trim().length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Response message is required'
      });
    }

    if (!req.params.id || req.params.id === 'undefined') {
      return res.status(400).json({
        success: false,
        message: 'Invalid complaint ID'
      });
    }

    const complaint = await Complaint.findById(req.params.id);
    if (!complaint) {
      return res.status(404).json({
        success: false,
        message: 'Complaint not found'
      });
    }

    const response = {
      author: req.user.name,
      authorId: req.user.id,
      message: typeof message === 'string' ? message.trim() : message.message?.trim() || '',
      isOfficial: true
    };

    complaint.responses.push(response);
    
    // Update status to under_review if it's still submitted
    if (complaint.status === 'submitted') {
      complaint.status = 'under_review';
      complaint.assignedTo = req.user.id;
    }

    await complaint.save();
    await complaint.populate('responses.authorId', 'name role');

    res.json({
      success: true,
      message: 'Response added successfully',
      response: complaint.responses[complaint.responses.length - 1]
    });
  } catch (error) {
    console.error('Add response error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error adding response'
    });
  }
});

// @desc    Assign complaint to admin
// @route   PATCH /api/complaints/:id/assign
// @access  Private/Admin
router.patch('/:id/assign', protect, adminOnly, async (req, res) => {
  try {
    const { assignedTo } = req.body;

    const complaint = await Complaint.findById(req.params.id);
    if (!complaint) {
      return res.status(404).json({
        success: false,
        message: 'Complaint not found'
      });
    }

    // Verify assigned user exists and is admin
    const assignedUser = await User.findById(assignedTo);
    if (!assignedUser || !assignedUser.isAdmin) {
      return res.status(400).json({
        success: false,
        message: 'Invalid user assignment'
      });
    }

    complaint.assignedTo = assignedTo;
    if (complaint.status === 'submitted') {
      complaint.status = 'under_review';
    }

    await complaint.save();
    await complaint.populate('assignedTo', 'name email role');

    return res.json({
      success: true,
      message: 'Complaint assigned successfully',
      complaint
    });
  } catch (error) {
    console.error('Assign complaint error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error assigning complaint'
    });
  }
});

// @desc    Get complaint statistics
// @route   GET /api/complaints/stats/overview
// @access  Private/Admin
router.get('/stats/overview', protect, adminOnly, async (req, res) => {
  try {
    const totalComplaints = await Complaint.countDocuments();
    const pendingComplaints = await Complaint.countDocuments({ status: 'submitted' });
    const underReviewComplaints = await Complaint.countDocuments({ status: 'under_review' });
    const resolvedComplaints = await Complaint.countDocuments({ status: 'resolved' });

    // Complaints by category
    const complaintsByCategory = await Complaint.aggregate([
      { $group: { _id: '$category', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);

    // Complaints by priority
    const complaintsByPriority = await Complaint.aggregate([
      { $group: { _id: '$priority', count: { $sum: 1 } } }
    ]);

    // Recent complaints (last 30 days)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    
    const recentComplaints = await Complaint.countDocuments({
      createdAt: { $gte: thirtyDaysAgo }
    });

    // Average resolution time
    const resolvedComplaintsWithTime = await Complaint.find({
      status: 'resolved',
      resolvedAt: { $exists: true }
    }).select('createdAt resolvedAt');

    let avgResolutionTime = 0;
    if (resolvedComplaintsWithTime.length > 0) {
      const totalTime = resolvedComplaintsWithTime.reduce((sum, complaint) => {
        return sum + (complaint.resolvedAt - complaint.createdAt);
      }, 0);
      avgResolutionTime = Math.round(totalTime / resolvedComplaintsWithTime.length / (1000 * 60 * 60 * 24)); // in days
    }

    return res.json({
      success: true,
      stats: {
        totalComplaints,
        pendingComplaints,
        underReviewComplaints,
        resolvedComplaints,
        recentComplaints,
        avgResolutionTime,
        complaintsByCategory,
        complaintsByPriority
      }
    });
  } catch (error) {
    console.error('Get complaint stats error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error fetching complaint statistics'
    });
  }
});

// @desc    Delete complaint (Admin only)
// @route   DELETE /api/complaints/:id
// @access  Private/Admin
router.delete('/:id', protect, adminOnly, async (req, res) => {
  try {
    if (!req.params.id || req.params.id === 'undefined') {
      return res.status(400).json({
        success: false,
        message: 'Invalid complaint ID'
      });
    }

    const complaint = await Complaint.findById(req.params.id);
    if (!complaint) {
      return res.status(404).json({
        success: false,
        message: 'Complaint not found'
      });
    }

    await Complaint.findByIdAndDelete(req.params.id);

    return res.json({
      success: true,
      message: 'Complaint deleted successfully'
    });
  } catch (error) {
    console.error('Delete complaint error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error deleting complaint'
    });
  }
});

module.exports = router;