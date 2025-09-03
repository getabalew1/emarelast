const express = require('express');
const Election = require('../models/Election');
const User = require('../models/User');
const { protect, adminOnly, optionalAuth } = require('../middleware/auth');
const { validateElection } = require('../middleware/validation');

const router = express.Router();

// @desc    Get all elections
// @route   GET /api/elections
// @access  Public
router.get('/', optionalAuth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const { status, type, search } = req.query;

    // Build query
    let query = {};
    
    // Only show public elections to non-admin users
    if (!req.user || !req.user.isAdmin) {
      query.isPublic = true;
    }

    if (status) query.status = status;
    if (type) query.electionType = type;
    
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }

    const elections = await Election.find(query)
      .populate('createdBy', 'name email role')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await Election.countDocuments(query);

    // Update election status based on current date
    const now = new Date();
    for (let election of elections) {
      let needsUpdate = false;
      
      if (election.startDate > now && election.status !== 'upcoming') {
        election.status = 'upcoming';
        needsUpdate = true;
      } else if (election.startDate <= now && election.endDate > now && election.status !== 'active') {
        election.status = 'active';
        needsUpdate = true;
      } else if (election.endDate <= now && election.status !== 'completed') {
        election.status = 'completed';
        needsUpdate = true;
      }
      
      if (needsUpdate) {
        await election.save();
      }
    }

    return res.json({
      success: true,
      count: elections.length,
      total,
      page,
      pages: Math.ceil(total / limit),
      elections,
      data: elections // Add data field for compatibility
    });
  } catch (error) {
    console.error('Get elections error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error fetching elections'
    });
  }
});

// @desc    Get single election
// @route   GET /api/elections/:id
// @access  Public
router.get('/:id', optionalAuth, async (req, res) => {
  try {
    const election = await Election.findById(req.params.id)
      .populate('createdBy', 'name email role')
      .populate('voters.user', 'name email studentId');

    if (!election) {
      return res.status(404).json({
        success: false,
        message: 'Election not found'
      });
    }

    // Check if election is public for non-admin users
    if ((!req.user || !req.user.isAdmin) && !election.isPublic) {
      return res.status(404).json({
        success: false,
        message: 'Election not found'
      });
    }

    // Update election status if needed
    const now = new Date();
    let needsUpdate = false;
    
    if (election.startDate > now && election.status !== 'upcoming') {
      election.status = 'upcoming';
      needsUpdate = true;
    } else if (election.startDate <= now && election.endDate > now && election.status !== 'active') {
      election.status = 'active';
      needsUpdate = true;
    } else if (election.endDate <= now && election.status !== 'completed') {
      election.status = 'completed';
      needsUpdate = true;
    }
    
    if (needsUpdate) {
      await election.save();
    }

    // Hide voter details for non-admin users
    if (!req.user || !req.user.isAdmin) {
      election.voters = election.voters.map(voter => ({
        votedAt: voter.votedAt
      }));
    }

    res.json({
      success: true,
      election
    });
  } catch (error) {
    console.error('Get election error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error fetching election'
    });
  }
});

// @desc    Create new election
// @route   POST /api/elections
// @access  Private/Admin
router.post('/', protect, adminOnly, validateElection, async (req, res) => {
  try {
    const { title, description, startDate, endDate, candidates, electionType, rules, isPublic } = req.body;

    console.log('Received election data:', req.body);
    console.log('User creating election:', req.user);
    // Validate dates
    const start = new Date(startDate);
    const end = new Date(endDate);
    const now = new Date();

    console.log('Date validation:', { start, end, now });
    if (start < now) {
      return res.status(400).json({
        success: false,
        message: 'Start date cannot be in the past'
      });
    }

    if (end <= start) {
      return res.status(400).json({
        success: false,
        message: 'End date must be after start date'
      });
    }

    // Get total eligible voters (all active students)
    const eligibleVoters = await User.countDocuments({ 
      role: 'student', 
      isActive: true 
    });

    const electionData = {
      title,
      description,
      startDate: start,
      endDate: end,
      candidates: candidates || [],
      electionType: electionType || 'general',
      rules: rules || [],
      isPublic: isPublic !== false,
      eligibleVoters,
      createdBy: req.user._id || req.user.id
    };

    console.log('Creating election with data:', electionData);
    const election = await Election.create(electionData);

    await election.populate('createdBy', 'name email role');

    console.log('Election created successfully:', election);
    res.status(201).json({
      success: true,
      message: 'Election created successfully',
      election
    });
  } catch (error) {
    console.error('Create election error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error creating election',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @desc    Update election
// @route   PUT /api/elections/:id
// @access  Private/Admin
router.put('/:id', protect, adminOnly, async (req, res) => {
  try {
    const { title, description, startDate, endDate, candidates, rules, isPublic } = req.body;

    const election = await Election.findById(req.params.id);
    if (!election) {
      return res.status(404).json({
        success: false,
        message: 'Election not found'
      });
    }

    // Don't allow updates to active or completed elections
    if (election.status === 'active' || election.status === 'completed') {
      return res.status(400).json({
        success: false,
        message: 'Cannot update active or completed elections'
      });
    }

    // Validate dates if provided
    if (startDate || endDate) {
      const start = new Date(startDate || election.startDate);
      const end = new Date(endDate || election.endDate);
      const now = new Date();

      if (start < now) {
        return res.status(400).json({
          success: false,
          message: 'Start date cannot be in the past'
        });
      }

      if (end <= start) {
        return res.status(400).json({
          success: false,
          message: 'End date must be after start date'
        });
      }

      election.startDate = start;
      election.endDate = end;
    }

    // Update fields
    if (title) election.title = title;
    if (description) election.description = description;
    if (candidates) election.candidates = candidates;
    if (rules) election.rules = rules;
    if (typeof isPublic === 'boolean') election.isPublic = isPublic;

    await election.save();

    res.json({
      success: true,
      message: 'Election updated successfully',
      election
    });
  } catch (error) {
    console.error('Update election error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error updating election'
    });
  }
});

// @desc    Delete election
// @route   DELETE /api/elections/:id
// @access  Private/Admin
router.delete('/:id', protect, adminOnly, async (req, res) => {
  try {
    const election = await Election.findById(req.params.id);
    if (!election) {
      return res.status(404).json({
        success: false,
        message: 'Election not found'
      });
    }

    // Don't allow deletion of active elections
    if (election.status === 'active') {
      return res.status(400).json({
        success: false,
        message: 'Cannot delete active elections'
      });
    }

    await Election.findByIdAndDelete(req.params.id);

    res.json({
      success: true,
      message: 'Election deleted successfully'
    });
  } catch (error) {
    console.error('Delete election error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error deleting election'
    });
  }
});

// @desc    Vote in election
// @route   POST /api/elections/:id/vote
// @access  Private
router.post('/:id/vote', protect, async (req, res) => {
  try {
    const { candidateId } = req.body;

    if (!candidateId) {
      return res.status(400).json({
        success: false,
        message: 'Candidate ID is required'
      });
    }

    // Prevent admins from voting
    if (req.user.isAdmin || req.user.role === 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Administrators cannot vote in elections'
      });
    }

    const election = await Election.findById(req.params.id);
    if (!election) {
      return res.status(404).json({
        success: false,
        message: 'Election not found'
      });
    }

    // Check if election is active
    if (election.status !== 'active') {
      return res.status(400).json({
        success: false,
        message: 'Election is not currently active'
      });
    }

    // Check if user has already voted
    if (election.hasUserVoted(req.user._id || req.user.id)) {
      return res.status(400).json({
        success: false,
        message: 'You have already voted in this election'
      });
    }

    // Find the candidate
    const candidate = election.candidates.id(candidateId);
    if (!candidate) {
      return res.status(400).json({
        success: false,
        message: 'Invalid candidate'
      });
    }

    // Record the vote
    election.voters.push({
      user: req.user._id || req.user.id,
      candidate: candidateId,
      ipAddress: req.ip
    });

    // Update candidate vote count
    candidate.votes += 1;
    candidate.voters.push(req.user.id);

    // Update total votes
    election.totalVotes += 1;

    await election.save();

    // Add election to user's voted elections
    await User.findByIdAndUpdate(req.user._id || req.user.id, {
      $addToSet: { votedElections: election._id }
    });

    res.json({
      success: true,
      message: 'Vote cast successfully',
      election: {
        id: election._id,
        totalVotes: election.totalVotes,
        hasVoted: true
      }
    });
  } catch (error) {
    console.error('Vote error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error casting vote'
    });
  }
});

// @desc    Announce election results
// @route   POST /api/elections/:id/announce
// @access  Private/Admin
router.post('/:id/announce', protect, adminOnly, async (req, res) => {
  try {
    const election = await Election.findById(req.params.id);
    if (!election) {
      return res.status(404).json({
        success: false,
        message: 'Election not found'
      });
    }

    if (election.status !== 'completed') {
      return res.status(400).json({
        success: false,
        message: 'Can only announce results for completed elections'
      });
    }

    election.resultsPublished = true;
    election.publishedAt = new Date();
    await election.save();

    res.json({
      success: true,
      message: 'Election results announced successfully',
      winner: election.getWinner()
    });
  } catch (error) {
    console.error('Announce results error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error announcing results'
    });
  }
});

// @desc    Get election statistics
// @route   GET /api/elections/stats/overview
// @access  Private/Admin
router.get('/stats/overview', protect, adminOnly, async (req, res) => {
  try {
    const totalElections = await Election.countDocuments();
    const activeElections = await Election.countDocuments({ status: 'active' });
    const upcomingElections = await Election.countDocuments({ status: 'upcoming' });
    const completedElections = await Election.countDocuments({ status: 'completed' });

    // Elections by type
    const electionsByType = await Election.aggregate([
      { $group: { _id: '$electionType', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);

    // Total votes cast
    const voteStats = await Election.aggregate([
      { $group: { _id: null, totalVotes: { $sum: '$totalVotes' }, avgTurnout: { $avg: '$turnoutPercentage' } } }
    ]);

    // Recent elections (last 90 days)
    const ninetyDaysAgo = new Date();
    ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 90);
    
    const recentElections = await Election.countDocuments({
      createdAt: { $gte: ninetyDaysAgo }
    });

    res.json({
      success: true,
      stats: {
        totalElections,
        activeElections,
        upcomingElections,
        completedElections,
        recentElections,
        totalVotes: voteStats[0]?.totalVotes || 0,
        avgTurnout: Math.round(voteStats[0]?.avgTurnout || 0),
        electionsByType
      }
    });
  } catch (error) {
    console.error('Get election stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error fetching election statistics'
    });
  }
});

module.exports = router;