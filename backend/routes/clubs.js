const express = require('express');
const Club = require('../models/Club');
const User = require('../models/User');
const { protect, adminOnly, optionalAuth } = require('../middleware/auth');
const { validateClub } = require('../middleware/validation');

const router = express.Router();

// @desc    Get all clubs
// @route   GET /api/clubs
// @access  Public
router.get('/', optionalAuth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const { category, status, search } = req.query;

    // Build query
    let query = {};
    
    // Only show active clubs to non-admin users
    if (!req.user || !req.user.isAdmin) {
      query.status = 'active';
    } else if (status) {
      query.status = status;
    }

    if (category) query.category = category;
    
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }

    const clubs = await Club.find(query)
      .populate('leadership.president', 'name email profileImage')
      .populate('leadership.vicePresident', 'name email profileImage')
      .populate('leadership.secretary', 'name email profileImage')
      .populate('leadership.treasurer', 'name email profileImage')
      .sort({ name: 1 })
      .skip(skip)
      .limit(limit);

    const total = await Club.countDocuments(query);

    // Transform clubs to include member count and event count
    const transformedClubs = clubs.map(club => ({
      id: club._id,
      name: club.name,
      description: club.description,
      category: club.category,
      founded: club.founded,
      image: club.image,
      members: club.members ? club.members.length : 0,
      events: club.events ? club.events.length : 0,
      status: club.status,
      contactEmail: club.contactEmail,
      meetingSchedule: club.meetingSchedule,
      leadership: club.leadership,
      socialMedia: club.socialMedia,
      createdAt: club.createdAt
    }));

    return res.json({
      success: true,
      count: transformedClubs.length,
      total,
      page,
      pages: Math.ceil(total / limit),
      clubs: transformedClubs,
      data: transformedClubs
    });
  } catch (error) {
    console.error('Get clubs error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error fetching clubs',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @desc    Get single club
// @route   GET /api/clubs/:id
// @access  Public
router.get('/:id', optionalAuth, async (req, res) => {
  try {
    const club = await Club.findById(req.params.id)
      .populate('members.user', 'name email studentId department year profileImage')
      .populate('leadership.president', 'name email studentId profileImage')
      .populate('leadership.vicePresident', 'name email studentId profileImage')
      .populate('leadership.secretary', 'name email studentId profileImage')
      .populate('leadership.treasurer', 'name email studentId profileImage')
      .populate('events.attendees', 'name email profileImage');

    if (!club) {
      return res.status(404).json({
        success: false,
        message: 'Club not found'
      });
    }

    // Check if club is active for non-admin users
    if ((!req.user || !req.user.isAdmin) && club.status !== 'active') {
      return res.status(404).json({
        success: false,
        message: 'Club not found'
      });
    }

    res.json({
      success: true,
      club
    });
  } catch (error) {
    console.error('Get club error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error fetching club',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @desc    Create new club
// @route   POST /api/clubs
// @access  Private/Admin
router.post('/', protect, adminOnly, validateClub, async (req, res) => {
  try {
    const { name, description, category, founded, image, contactEmail, meetingSchedule, requirements } = req.body;

    console.log('Received club data:', req.body);
    console.log('User creating club:', req.user);
    // Check if club name already exists
    const existingClub = await Club.findOne({ 
      name: { $regex: new RegExp(`^${name}$`, 'i') } 
    });
    if (existingClub) {
      return res.status(409).json({
        success: false,
        message: 'Club with this name already exists'
      });
    }

    const clubData = {
      name,
      description,
      category,
      founded: founded || new Date().getFullYear().toString(),
      image: image || 'https://images.pexels.com/photos/3184291/pexels-photo-3184291.jpeg?auto=compress&cs=tinysrgb&w=400',
      contactEmail,
      meetingSchedule,
      requirements,
      status: 'active'
    };

    console.log('Creating club with data:', clubData);
    const club = await Club.create(clubData);

    console.log('Club created successfully:', club);

    res.status(201).json({
      success: true,
      message: 'Club created successfully',
      club
    });
  } catch (error) {
    console.error('Create club error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error creating club',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @desc    Update club
// @route   PUT /api/clubs/:id
// @access  Private/Admin
router.put('/:id', protect, adminOnly, async (req, res) => {
  try {
    const { name, description, category, image, contactEmail, meetingSchedule, requirements, status } = req.body;

    const club = await Club.findById(req.params.id);
    if (!club) {
      return res.status(404).json({
        success: false,
        message: 'Club not found'
      });
    }

    // Check if new name conflicts with existing club
    if (name && name !== club.name) {
      const existingClub = await Club.findOne({ 
        name: { $regex: new RegExp(`^${name}$`, 'i') },
        _id: { $ne: req.params.id }
      });
      if (existingClub) {
        return res.status(409).json({
          success: false,
          message: 'Club with this name already exists'
        });
      }
    }

    // Update fields
    if (name) club.name = name;
    if (description) club.description = description;
    if (category) club.category = category;
    if (image) club.image = image;
    if (contactEmail) club.contactEmail = contactEmail;
    if (meetingSchedule) club.meetingSchedule = meetingSchedule;
    if (requirements) club.requirements = requirements;
    if (status) club.status = status;

    await club.save();

    res.json({
      success: true,
      message: 'Club updated successfully',
      club
    });
  } catch (error) {
    console.error('Update club error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error updating club',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @desc    Delete club
// @route   DELETE /api/clubs/:id
// @access  Private/Admin
router.delete('/:id', protect, adminOnly, async (req, res) => {
  try {
    const club = await Club.findById(req.params.id);
    if (!club) {
      return res.status(404).json({
        success: false,
        message: 'Club not found'
      });
    }

    // Remove club from users' joinedClubs array
    await User.updateMany(
      { joinedClubs: club._id },
      { $pull: { joinedClubs: club._id } }
    );

    await Club.findByIdAndDelete(req.params.id);

    res.json({
      success: true,
      message: 'Club deleted successfully'
    });
  } catch (error) {
    console.error('Delete club error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error deleting club',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @desc    Join club
// @route   POST /api/clubs/:id/join
// @access  Private
router.post('/:id/join', protect, async (req, res) => {
  try {
    const { fullName, department, year, background } = req.body;

    if (!fullName || !department || !year) {
      return res.status(400).json({
        success: false,
        message: 'Full name, department, and year are required'
      });
    }

    const club = await Club.findById(req.params.id);
    if (!club) {
      return res.status(404).json({
        success: false,
        message: 'Club not found'
      });
    }

    if (club.status !== 'active') {
      return res.status(400).json({
        success: false,
        message: 'Cannot join inactive club'
      });
    }

    // Check if user is already a member
    const existingMember = club.members.find(member => 
      member.user.toString() === req.user._id.toString()
    );
    
    if (existingMember) {
      if (existingMember.status === 'pending') {
        return res.status(400).json({
          success: false,
          message: 'Your join request is already pending approval'
        });
      }
      return res.status(400).json({
        success: false,
        message: 'You are already a member of this club'
      });
    }

    // Add user to club members
    club.members.push({
      user: req.user._id,
      fullName: fullName || req.user.name,
      department: department || req.user.department,
      year: year || req.user.year,
      background,
      role: 'member',
      status: 'pending',
      joinedAt: new Date()
    });

    await club.save();

    res.json({
      success: true,
      message: 'Join request submitted successfully. Waiting for admin approval.'
    });
  } catch (error) {
    console.error('Join club error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error joining club',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @desc    Approve club member
// @route   PATCH /api/clubs/:id/members/:memberId/approve
// @access  Private/Admin
router.patch('/:id/members/:memberId/approve', protect, adminOnly, async (req, res) => {
  try {
    const club = await Club.findById(req.params.id);
    if (!club) {
      return res.status(404).json({
        success: false,
        message: 'Club not found'
      });
    }

    const member = club.members.id(req.params.memberId);
    if (!member) {
      return res.status(404).json({
        success: false,
        message: 'Member not found'
      });
    }

    member.status = 'approved';
    member.approvedAt = new Date();
    await club.save();

    // Add club to user's joinedClubs
    await User.findByIdAndUpdate(member.user, {
      $addToSet: { joinedClubs: club._id }
    });

    res.json({
      success: true,
      message: 'Member approved successfully'
    });
  } catch (error) {
    console.error('Approve member error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error approving member'
    });
  }
});

// @desc    Reject club member
// @route   PATCH /api/clubs/:id/members/:memberId/reject
// @access  Private/Admin
router.patch('/:id/members/:memberId/reject', protect, adminOnly, async (req, res) => {
  try {
    const club = await Club.findById(req.params.id);
    if (!club) {
      return res.status(404).json({
        success: false,
        message: 'Club not found'
      });
    }

    const member = club.members.id(req.params.memberId);
    if (!member) {
      return res.status(404).json({
        success: false,
        message: 'Member not found'
      });
    }

    member.status = 'rejected';
    await club.save();

    res.json({
      success: true,
      message: 'Member rejected successfully'
    });
  } catch (error) {
    console.error('Reject member error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error rejecting member'
    });
  }
});

// @desc    Get club join requests
// @route   GET /api/clubs/:id/join-requests
// @access  Private/Admin
router.get('/:id/join-requests', protect, adminOnly, async (req, res) => {
  try {
    const club = await Club.findById(req.params.id)
      .populate('members.user', 'name username email profileImage');

    if (!club) {
      return res.status(404).json({
        success: false,
        message: 'Club not found'
      });
    }

    const pendingRequests = club.members.filter(member => member.status === 'pending');

    res.json({
      success: true,
      count: pendingRequests.length,
      requests: pendingRequests
    });
  } catch (error) {
    console.error('Get join requests error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error fetching join requests'
    });
  }
});

// @desc    Leave club
// @route   POST /api/clubs/:id/leave
// @access  Private
router.post('/:id/leave', protect, async (req, res) => {
  try {
    const club = await Club.findById(req.params.id);
    if (!club) {
      return res.status(404).json({
        success: false,
        message: 'Club not found'
      });
    }

    // Check if user is a member
    const memberIndex = club.members.findIndex(member => 
      member.user.toString() === req.user._id.toString()
    );
    
    if (memberIndex === -1) {
      return res.status(400).json({
        success: false,
        message: 'You are not a member of this club'
      });
    }

    // Remove user from club members
    club.members.splice(memberIndex, 1);
    await club.save();

    // Remove club from user's joinedClubs
    await User.findByIdAndUpdate(req.user._id, {
      $pull: { joinedClubs: club._id }
    });

    res.json({
      success: true,
      message: 'Successfully left the club'
    });
  } catch (error) {
    console.error('Leave club error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error leaving club'
    });
  }
});

// @desc    Get club statistics
// @route   GET /api/clubs/stats/overview
// @access  Private/Admin
router.get('/stats/overview', protect, adminOnly, async (req, res) => {
  try {
    const totalClubs = await Club.countDocuments();
    const activeClubs = await Club.countDocuments({ status: 'active' });
    const pendingClubs = await Club.countDocuments({ status: 'pending' });
    const inactiveClubs = await Club.countDocuments({ status: 'inactive' });

    // Clubs by category
    const clubsByCategory = await Club.aggregate([
      { $match: { category: { $exists: true, $ne: null } } },
      { $group: { _id: '$category', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);

    // Total members across all clubs
    const memberStats = await Club.aggregate([
      { $project: { memberCount: { $size: '$members' } } },
      { $group: { _id: null, totalMembers: { $sum: '$memberCount' }, avgMembers: { $avg: '$memberCount' } } }
    ]);

    // Most popular clubs
    const popularClubs = await Club.aggregate([
      { $project: { name: 1, memberCount: { $size: '$members' } } },
      { $sort: { memberCount: -1 } },
      { $limit: 5 }
    ]);

    res.json({
      success: true,
      stats: {
        totalClubs,
        activeClubs,
        pendingClubs,
        inactiveClubs,
        totalMembers: memberStats[0]?.totalMembers || 0,
        avgMembers: Math.round(memberStats[0]?.avgMembers || 0),
        clubsByCategory,
        popularClubs
      }
    });
  } catch (error) {
    console.error('Get club stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error fetching club statistics'
    });
  }
});

module.exports = router;