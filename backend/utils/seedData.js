const mongoose = require('mongoose');
const User = require('../models/User');
const Club = require('../models/Club');
const Post = require('../models/Post');
const Election = require('../models/Election');
const Complaint = require('../models/Complaint');
require('dotenv').config();

const seedData = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/student_union_db');
    console.log('Connected to MongoDB for seeding...');

    // Get admin users
    const president = await User.findOne({ email: 'president@dbu.edu.et' });
    const academicAdmin = await User.findOne({ email: 'academic@dbu.edu.et' });
    const clubsAdmin = await User.findOne({ email: 'clubs@dbu.edu.et' });
    const systemAdmin = await User.findOne({ email: 'admin@dbu.edu.et' });

    // Use system admin as fallback if specific admins don't exist
    const defaultAuthor = president || academicAdmin || clubsAdmin || systemAdmin;

    if (!defaultAuthor) {
      console.log('No admin users found, skipping seeding');
      return;
    }

    // Seed Clubs
    const clubs = [
      {
        name: 'Debate Society',
        description: 'Developing critical thinking and public speaking skills through competitive debates',
        category: 'Academic',
        founded: '2015',
        image: 'https://images.pexels.com/photos/3184291/pexels-photo-3184291.jpeg?auto=compress&cs=tinysrgb&w=400',
        status: 'active',
        contactEmail: 'debate@dbu.edu.et',
        meetingSchedule: 'Every Friday at 3:00 PM',
        requirements: 'Open to all students interested in debate and public speaking'
      },
      {
        name: 'Football Club',
        description: 'University football team competing in inter-university tournaments',
        category: 'Sports',
        founded: '2012',
        image: 'https://images.pexels.com/photos/274506/pexels-photo-274506.jpeg?auto=compress&cs=tinysrgb&w=400',
        status: 'active',
        contactEmail: 'football@dbu.edu.et',
        meetingSchedule: 'Training: Monday, Wednesday, Friday at 4:00 PM',
        requirements: 'Basic fitness level required'
      },
      {
        name: 'Drama Club',
        description: 'Theatrical performances and creative expression through drama and arts',
        category: 'Cultural',
        founded: '2016',
        image: 'https://images.pexels.com/photos/3184338/pexels-photo-3184338.jpeg?auto=compress&cs=tinysrgb&w=400',
        status: 'active',
        contactEmail: 'drama@dbu.edu.et',
        meetingSchedule: 'Every Tuesday and Thursday at 5:00 PM',
        requirements: 'Passion for performing arts'
      },
      {
        name: 'Computer Science Society',
        description: 'Programming workshops, hackathons, and tech innovation projects',
        category: 'Technology',
        founded: '2014',
        image: 'https://images.pexels.com/photos/3861958/pexels-photo-3861958.jpeg?auto=compress&cs=tinysrgb&w=400',
        status: 'active',
        contactEmail: 'cs@dbu.edu.et',
        meetingSchedule: 'Every Saturday at 2:00 PM',
        requirements: 'Basic programming knowledge preferred'
      }
    ];

    for (const clubData of clubs) {
      const existingClub = await Club.findOne({ name: clubData.name });
      if (!existingClub) {
        await Club.create(clubData);
        console.log(`Club created: ${clubData.name}`);
      }
    }

    // Seed Posts
    const posts = [
      {
        title: 'Annual Cultural Festival 2024',
        content: 'Join us for the biggest cultural celebration of the year! Experience diverse performances, traditional foods, and cultural exhibitions from students representing various regions of Ethiopia.',
        type: 'Event',
        category: 'Cultural',
        date: new Date('2024-03-15'),
        location: 'Main Campus Auditorium',
        time: '9:00 AM - 6:00 PM',
        eventDate: new Date('2024-03-15'),
        author: defaultAuthor._id,
        status: 'published'
      },
      {
        title: 'New Library Digital Resources Available',
        content: 'The university library has expanded its digital collection with over 10,000 new e-books and research papers. Students can now access these resources 24/7 through the online portal.',
        type: 'News',
        category: 'Academic',
        date: new Date('2024-02-10'),
        author: defaultAuthor._id,
        status: 'published'
      },
      {
        title: 'Important: Exam Schedule Changes',
        content: 'Due to unforeseen circumstances, the final exam schedule has been updated. Please check the academic portal for the latest schedule and plan accordingly.',
        type: 'Announcement',
        category: 'Academic',
        date: new Date('2024-02-05'),
        important: true,
        author: defaultAuthor._id,
        status: 'published'
      },
      {
        title: 'Inter-University Football Championship',
        content: 'Our football team will be competing in the regional championship. Come support our team as they represent DBU in this prestigious tournament.',
        type: 'Event',
        category: 'Sports',
        date: new Date('2024-02-20'),
        location: 'DBU Sports Complex',
        time: '2:00 PM',
        eventDate: new Date('2024-02-20'),
        author: defaultAuthor._id,
        status: 'published'
      }
    ];

    for (const postData of posts) {
      const existingPost = await Post.findOne({ title: postData.title });
      if (!existingPost) {
        await Post.create(postData);
        console.log(`Post created: ${postData.title}`);
      }
    }

    // Seed Elections
    const elections = [
      {
        title: 'Student Union President Election 2024',
        description: 'Vote for the next Student Union President who will represent all students and lead various initiatives for the upcoming academic year.',
        startDate: new Date('2024-03-01'),
        endDate: new Date('2024-03-07'),
        status: 'upcoming',
        electionType: 'president',
        eligibleVoters: 12547,
        createdBy: defaultAuthor._id,
        candidates: [
          {
            name: 'Hewan Tadesse',
            username: 'dbu20210001',
            department: 'Computer Science',
            year: '4th Year',
            academicYear: '4th Year',
            position: 'President',
            profileImage: 'https://images.pexels.com/photos/3763188/pexels-photo-3763188.jpeg?auto=compress&cs=tinysrgb&w=400',
            platform: ['Student Welfare', 'Academic Excellence', 'Campus Infrastructure'],
            biography: 'Experienced student leader with a passion for improving student life and academic standards.',
            votes: 0
          },
          {
            name: 'Dawit Mekonnen',
            username: 'dbu20210002',
            department: 'Engineering',
            year: '4th Year',
            academicYear: '4th Year',
            position: 'President',
            profileImage: 'https://images.pexels.com/photos/2182970/pexels-photo-2182970.jpeg?auto=compress&cs=tinysrgb&w=400',
            platform: ['Innovation Hub', 'Student Rights', 'Environmental Sustainability'],
            biography: 'Innovative thinker focused on bringing modern solutions to traditional student challenges.',
            votes: 0
          }
        ]
      }
    ];

    for (const electionData of elections) {
      const existingElection = await Election.findOne({ title: electionData.title });
      if (!existingElection) {
        await Election.create(electionData);
        console.log(`Election created: ${electionData.title}`);
      }
    }

    // Seed Sample Complaints
    const sampleStudent = await User.findOne({ username: 'dbu10304058' });
    
    if (sampleStudent) {
      const complaints = [
        {
          title: 'Library WiFi Connection Issues',
          description: 'The WiFi connection in the library has been very unstable for the past week, making it difficult to access online resources for research.',
          category: 'facilities',
          priority: 'medium',
          status: 'submitted',
          submittedBy: sampleStudent._id,
          branch: 'facilities'
        },
        {
          title: 'Dining Hall Food Quality Concerns',
          description: 'Recent meals have been consistently poor quality with limited variety. Many students are concerned about nutrition and food safety.',
          category: 'dining',
          priority: 'high',
          status: 'under_review',
          submittedBy: sampleStudent._id,
          branch: 'dining'
        }
      ];

      for (const complaintData of complaints) {
        const existingComplaint = await Complaint.findOne({ title: complaintData.title });
        if (!existingComplaint) {
          await Complaint.create(complaintData);
          console.log(`Complaint created: ${complaintData.title}`);
        }
      }
    }

    console.log('Sample data seeded successfully!');
    process.exit(0);

  } catch (error) {
    console.error('Error seeding data:', error);
    process.exit(1);
  }
};

// Run seeding if this file is executed directly
if (require.main === module) {
  seedData();
}

module.exports = { seedData };