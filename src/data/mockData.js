export const mockComplaints = [
  {
    id: "comp_1",
    title: "Library Access Issue",
    description: "Unable to access digital library resources from dormitory",
    category: "academic",
    priority: "medium",
    status: "resolved",
    submittedBy: "student_123",
    submittedAt: new Date("2024-01-15"),
    responses: [
      {
        id: "resp_1",
        author: "Academic Affairs",
        message: "We've contacted IT to resolve the VPN access issue.",
        timestamp: new Date("2024-01-16"),
      },
      {
        id: "resp_2",
        author: "Academic Affairs",
        message: "Issue has been resolved. Please try accessing again.",
        timestamp: new Date("2024-01-17"),
      },
    ],
  },
  {
    id: "comp_2",
    title: "Dining Hall Food Quality",
    description: "Recent meals have been consistently poor quality",
    category: "dining",
    priority: "high",
    status: "under_review",
    submittedBy: "student_456",
    submittedAt: new Date("2024-01-20"),
    responses: [
      {
        id: "resp_3",
        author: "Dining Services",
        message: "Thank you for your feedback. We're investigating this matter.",
        timestamp: new Date("2024-01-21"),
      },
    ],
  },
];

export const generateCaseId = () => {
  return "CASE-" + Date.now().toString().slice(-6);
};

export const mockElections = [
  {
    id: "1",
    title: "Student Union President Election 2024",
    description: "Vote for the next Student Union President who will represent all students",
    status: "active",
    startDate: "2024-02-01",
    endDate: "2024-02-07",
    totalVotes: 8547,
    eligibleVoters: 12547,
    candidates: [
      {
        id: "1",
        name: "Hewan Tadesse",
        position: "President",
        votes: 4523,
        profileImage: "https://images.pexels.com/photos/3763188/pexels-photo-3763188.jpeg?auto=compress&cs=tinysrgb&w=400",
        platform: ["Student Welfare", "Academic Excellence", "Campus Infrastructure"],
      },
      {
        id: "2",
        name: "Dawit Mekonnen",
        position: "President",
        votes: 4024,
        profileImage: "https://images.pexels.com/photos/2182970/pexels-photo-2182970.jpeg?auto=compress&cs=tinysrgb&w=400",
        platform: ["Innovation Hub", "Student Rights", "Environmental Sustainability"],
      },
    ],
  },
  {
    id: "2",
    title: "Branch Leader Elections",
    description: "Elections for various branch leadership positions",
    status: "upcoming",
    startDate: "2024-02-15",
    endDate: "2024-02-20",
    totalVotes: 0,
    eligibleVoters: 12547,
    candidates: [],
  },
];

export const mockClubs = [
  {
    id: "club_1",
    name: "Debate Society",
    category: "Academic",
    members: 45,
    description: "Developing critical thinking and public speaking skills through competitive debates",
    image: "https://images.pexels.com/photos/3184291/pexels-photo-3184291.jpeg?auto=compress&cs=tinysrgb&w=400",
    events: 12,
    founded: "2015",
    status: "active",
  },
  {
    id: "club_2",
    name: "Football Club",
    category: "Sports",
    members: 60,
    description: "University football team competing in inter-university tournaments",
    image: "https://images.pexels.com/photos/274506/pexels-photo-274506.jpeg?auto=compress&cs=tinysrgb&w=400",
    events: 8,
    founded: "2012",
    status: "active",
  },
  {
    id: "club_3",
    name: "Drama Club",
    category: "Cultural",
    members: 32,
    description: "Theatrical performances and creative expression through drama and arts",
    image: "https://images.pexels.com/photos/3184338/pexels-photo-3184338.jpeg?auto=compress&cs=tinysrgb&w=400",
    events: 15,
    founded: "2016",
    status: "active",
  },
  {
    id: "club_4",
    name: "Computer Science Society",
    category: "Technology",
    members: 78,
    description: "Programming workshops, hackathons, and tech innovation projects",
    image: "https://images.pexels.com/photos/3861958/pexels-photo-3861958.jpeg?auto=compress&cs=tinysrgb&w=400",
    events: 20,
    founded: "2014",
    status: "active",
  },
];