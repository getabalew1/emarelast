export const adminCredentials = [
  {
    id: "admin_1",
    name: "Alemnesh Tadesse",
    email: "president@dbu.edu.et",
    password: "admin123",
    role: "president",
    permissions: ["all", "emergency_override", "system_admin"],
  },
  {
    id: "admin_2",
    name: "Bekele Mekonnen",
    email: "studentdin@dbu.edu.et",
    password: "admin123",
    role: "student_din",
    permissions: ["mediation", "oversight", "reports"],
  },
  {
    id: "admin_3",
    name: "Hewan Tadesse",
    email: "academic@dbu.edu.et",
    password: "admin123",
    role: "academic_affairs",
    permissions: ["academic_management", "student_records"],
  },
  {
    id: "admin_4",
    name: "Dawit Mekonnen",
    email: "clubs@dbu.edu.et",
    password: "admin123",
    role: "clubs_associations",
    permissions: ["club_approval", "event_management"],
  },
  {
    id: "admin_5",
    name: "Sara Ahmed",
    email: "dining@dbu.edu.et",
    password: "admin123",
    role: "dining_services",
    permissions: ["dining_management", "complaint_resolution"],
  },
  {
    id: "admin_6",
    name: "Michael Tesfaye",
    email: "sports@dbu.edu.et",
    password: "admin123",
    role: "sports_culture",
    permissions: ["sports_management", "cultural_events"],
  },
];

export const hasPermission = (adminCredential, permission) => {
  if (!adminCredential || !adminCredential.permissions) return false;
  return adminCredential.permissions.includes(permission) || adminCredential.permissions.includes("all");
};