const { body, validationResult } = require('express-validator');

// Handle validation errors
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }
  next();
};

// User validation rules
const validateUserRegistration = [
  body('name')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Name must be between 2 and 50 characters'),
  body('username')
    .matches(/^dbu\d{8}$/i)
    .withMessage('Username must start with dbu followed by 8 digits'),
  body('email')
    .optional()
    .isEmail()
    .withMessage('Please provide a valid email'),
  body('department')
    .notEmpty()
    .withMessage('Department is required'),
  body('year')
    .isIn(['1st Year', '2nd Year', '3rd Year', '4th Year', '5th Year'])
    .withMessage('Please select a valid academic year'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>])/)
    .withMessage('Password must contain uppercase, lowercase, digit, and symbol'),
  handleValidationErrors
];

const validateUserLogin = [
  body('username')
    .matches(/^dbu\d{8}$/i)
    .withMessage('Username must start with dbu followed by 8 digits'),
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
  handleValidationErrors
];

// Complaint validation rules
const validateComplaint = [
  body('title')
    .trim()
    .isLength({ min: 5, max: 200 })
    .withMessage('Title must be between 5 and 200 characters'),
  body('description')
    .trim()
    .isLength({ min: 10, max: 2000 })
    .withMessage('Description must be between 10 and 2000 characters'),
  body('category')
    .isIn(['academic', 'dining', 'housing', 'facilities', 'disciplinary', 'general'])
    .withMessage('Please select a valid category'),
  body('priority')
    .optional()
    .isIn(['low', 'medium', 'high'])
    .withMessage('Priority must be low, medium, or high'),
  handleValidationErrors
];

// Club validation rules
const validateClub = [
  body('name')
    .trim()
    .isLength({ min: 3, max: 100 })
    .withMessage('Club name must be between 3 and 100 characters'),
  body('description')
    .trim()
    .isLength({ min: 10, max: 1000 })
    .withMessage('Description must be between 10 and 1000 characters'),
  body('category')
    .isIn(['Academic', 'Sports', 'Cultural', 'Technology', 'Service', 'Arts', 'Religious', 'Professional'])
    .withMessage('Please select a valid category'),
  body('founded')
    .notEmpty()
    .withMessage('Founded year is required'),
  handleValidationErrors
];

// Election validation rules
const validateElection = [
  body('title')
    .trim()
    .isLength({ min: 5, max: 200 })
    .withMessage('Title must be between 5 and 200 characters'),
  body('description')
    .trim()
    .isLength({ min: 10, max: 1000 })
    .withMessage('Description must be between 10 and 1000 characters'),
  body('startDate')
    .isISO8601()
    .withMessage('Please provide a valid start date'),
  body('endDate')
    .isISO8601()
    .withMessage('Please provide a valid end date')
    .custom((endDate, { req }) => {
      if (new Date(endDate) <= new Date(req.body.startDate)) {
        throw new Error('End date must be after start date');
      }
      return true;
    }),
  handleValidationErrors
];

// Post validation rules
const validatePost = [
  body('title')
    .trim()
    .isLength({ min: 5, max: 200 })
    .withMessage('Title must be between 5 and 200 characters'),
  body('content')
    .trim()
    .isLength({ min: 10, max: 5000 })
    .withMessage('Content must be between 10 and 5000 characters'),
  body('type')
    .isIn(['News', 'Event', 'Announcement'])
    .withMessage('Type must be News, Event, or Announcement'),
  body('category')
    .optional()
    .isIn(['General', 'Campus', 'Academic', 'Sports', 'Research', 'Cultural'])
    .withMessage('Please select a valid category'),
  handleValidationErrors
];

// Contact validation rules
const validateContact = [
  body('name')
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Name must be between 2 and 100 characters'),
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  body('message')
    .trim()
    .isLength({ min: 10, max: 2000 })
    .withMessage('Message must be between 10 and 2000 characters'),
  body('category')
    .optional()
    .isIn(['academic', 'clubs', 'dining', 'sports', 'general'])
    .withMessage('Please select a valid category'),
  handleValidationErrors
];

module.exports = {
  validateUserRegistration,
  validateUserLogin,
  validateComplaint,
  validateClub,
  validateElection,
  validatePost,
  validateContact,
  handleValidationErrors
};