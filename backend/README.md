# Student Union Management System - Backend API

A comprehensive backend API for the Debre Berhan University Student Union Management System built with Node.js, Express, and MongoDB.

## Features

- **Authentication & Authorization**: JWT-based authentication with role-based access control
- **User Management**: Student and admin user management with different permission levels
- **Complaints System**: Submit, track, and manage student complaints with responses
- **Club Management**: Create, join, and manage student clubs and organizations
- **Elections**: Conduct secure student elections with voting capabilities
- **Posts & Announcements**: News, events, and announcements management
- **Contact System**: Handle contact messages and inquiries
- **File Upload**: Support for image uploads and file attachments
- **Statistics & Analytics**: Comprehensive reporting and analytics

## Tech Stack

- **Runtime**: Node.js
- **Framework**: Express.js
- **Database**: MongoDB with Mongoose ODM
- **Authentication**: JWT (JSON Web Tokens)
- **Validation**: Express Validator
- **Security**: Helmet, CORS, Rate Limiting
- **File Upload**: Multer
- **Email**: Nodemailer (optional)

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd backend
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Environment Setup**
   ```bash
   cp .env.example .env
   ```
   
   Update the `.env` file with your configuration:
   ```env
   PORT=5000
   NODE_ENV=development
   MONGODB_URI=mongodb://localhost:27017/student_union_db
   JWT_SECRET=your_super_secret_jwt_key_here
   JWT_EXPIRE=7d
   ```

4. **Start MongoDB**
   Make sure MongoDB is running on your system.

5. **Run the application**
   ```bash
   # Development mode
   npm run dev
   
   # Production mode
   npm start
   ```

6. **Seed sample data (optional)**
   ```bash
   node utils/seedData.js
   ```

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - User login
- `GET /api/auth/profile` - Get user profile
- `PUT /api/auth/profile` - Update user profile
- `PUT /api/auth/change-password` - Change password
- `POST /api/auth/logout` - Logout user

### Users (Admin only)
- `GET /api/users` - Get all users
- `GET /api/users/:id` - Get user by ID
- `PUT /api/users/:id` - Update user
- `DELETE /api/users/:id` - Delete user
- `GET /api/users/stats/overview` - Get user statistics

### Complaints
- `GET /api/complaints` - Get complaints (filtered by user role)
- `GET /api/complaints/:id` - Get single complaint
- `POST /api/complaints` - Create new complaint
- `PATCH /api/complaints/:id/status` - Update complaint status (Admin)
- `POST /api/complaints/:id/responses` - Add response to complaint (Admin)
- `PATCH /api/complaints/:id/assign` - Assign complaint to admin
- `GET /api/complaints/stats/overview` - Get complaint statistics (Admin)

### Clubs
- `GET /api/clubs` - Get all clubs
- `GET /api/clubs/:id` - Get single club
- `POST /api/clubs` - Create new club (Admin)
- `PUT /api/clubs/:id` - Update club (Admin)
- `DELETE /api/clubs/:id` - Delete club (Admin)
- `POST /api/clubs/:id/join` - Join club
- `POST /api/clubs/:id/leave` - Leave club
- `GET /api/clubs/stats/overview` - Get club statistics (Admin)

### Elections
- `GET /api/elections` - Get all elections
- `GET /api/elections/:id` - Get single election
- `POST /api/elections` - Create new election (Admin)
- `PUT /api/elections/:id` - Update election (Admin)
- `DELETE /api/elections/:id` - Delete election (Admin)
- `POST /api/elections/:id/vote` - Vote in election
- `POST /api/elections/:id/announce` - Announce results (Admin)
- `GET /api/elections/stats/overview` - Get election statistics (Admin)

### Posts
- `GET /api/posts` - Get all posts
- `GET /api/posts/:id` - Get single post
- `POST /api/posts` - Create new post (Admin)
- `PUT /api/posts/:id` - Update post (Admin)
- `DELETE /api/posts/:id` - Delete post (Admin)
- `POST /api/posts/:id/like` - Like/unlike post
- `POST /api/posts/:id/comments` - Add comment to post
- `POST /api/posts/:id/register` - Register for event
- `GET /api/posts/stats/overview` - Get post statistics (Admin)

### Contact
- `POST /api/contact` - Submit contact message
- `GET /api/contact` - Get all contact messages (Admin)
- `GET /api/contact/:id` - Get single contact message (Admin)
- `PATCH /api/contact/:id/status` - Update contact status (Admin)
- `POST /api/contact/:id/reply` - Reply to contact message (Admin)
- `PATCH /api/contact/:id/assign` - Assign contact message (Admin)
- `DELETE /api/contact/:id` - Delete contact message (Admin)
- `GET /api/contact/stats/overview` - Get contact statistics (Admin)

## User Roles

### Student
- Basic user with access to:
  - View clubs, elections, posts
  - Submit complaints
  - Join clubs
  - Vote in elections
  - Submit contact messages

### Admin Roles
- **President**: Full system access with emergency override capabilities
- **Student Din**: Mediation and oversight permissions
- **Academic Affairs**: Academic-related management
- **Clubs & Associations**: Club approval and event management
- **Dining Services**: Dining-related complaint resolution
- **Sports & Culture**: Sports and cultural event management

## Default Admin Accounts

The system creates default admin accounts on startup:

- **System Admin**: admin@dbu.edu.et (password: admin123)
- **President**: president@dbu.edu.et (password: admin123)
- **Student Din**: studentdin@dbu.edu.et (password: admin123)
- **Academic Affairs**: academic@dbu.edu.et (password: admin123)
- **Clubs Admin**: clubs@dbu.edu.et (password: admin123)
- **Dining Services**: dining@dbu.edu.et (password: admin123)
- **Sports & Culture**: sports@dbu.edu.et (password: admin123)

## Security Features

- JWT-based authentication
- Password hashing with bcrypt
- Rate limiting to prevent abuse
- CORS configuration
- Input validation and sanitization
- Role-based access control
- Secure headers with Helmet

## Database Schema

### User Model
- Personal information (name, email, student ID)
- Authentication (password, role, permissions)
- Profile data (department, year, joined clubs)
- Activity tracking (last login, voted elections)

### Complaint Model
- Complaint details (title, description, category)
- Status tracking (submitted, under review, resolved)
- Response system with admin replies
- Case ID generation and assignment

### Club Model
- Club information (name, description, category)
- Membership management
- Leadership structure
- Event tracking
- Budget management

### Election Model
- Election details (title, description, dates)
- Candidate management with voting
- Voter tracking and security
- Results calculation and announcement

### Post Model
- Content management (title, content, type)
- Event-specific fields (location, time, registration)
- Engagement features (likes, comments, views)
- Publishing and scheduling

### Contact Model
- Message details (name, email, subject, message)
- Status tracking and assignment
- Reply system for admin responses
- Priority and category management

## Error Handling

The API includes comprehensive error handling:
- Validation errors with detailed messages
- Authentication and authorization errors
- Database operation errors
- File upload errors
- Rate limiting errors

## Development

### Running Tests
```bash
npm test
```

### Code Structure
```
backend/
├── models/          # Database models
├── routes/          # API route handlers
├── middleware/      # Custom middleware
├── utils/           # Utility functions
├── uploads/         # File upload directory
├── server.js        # Main server file
└── package.json     # Dependencies and scripts
```

### Adding New Features

1. Create model in `models/` directory
2. Add routes in `routes/` directory
3. Implement middleware if needed
4. Add validation rules
5. Update documentation

## Deployment

### Environment Variables for Production
```env
NODE_ENV=production
PORT=5000
MONGODB_URI=mongodb://your-production-db-url
JWT_SECRET=your-very-secure-secret-key
```

### PM2 Deployment
```bash
npm install -g pm2
pm2 start server.js --name "student-union-api"
pm2 startup
pm2 save
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Support

For support and questions, please contact the development team or create an issue in the repository.