import React, { useState, useEffect } from "react";
import { Users, Calendar, Award, Search, Filter, Plus, MapPin, Mail, Phone, Globe } from "lucide-react";
import { motion } from "framer-motion";
import { useAuth } from "../../contexts/AuthContext";
import { apiService } from "../../services/api";
import toast from "react-hot-toast";

export function Clubs() {
  const { user } = useAuth();
  const [selectedCategory, setSelectedCategory] = useState("All");
  const [searchTerm, setSearchTerm] = useState("");
  const [clubs, setClubs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showNewClubForm, setShowNewClubForm] = useState(false);
  const [newClub, setNewClub] = useState({
    name: "",
    category: "Academic",
    description: "",
    imageFile: null,
    imagePreview: "",
    contactEmail: "",
    contactPhone: "",
    website: "",
    officeLocation: "",
    meetingSchedule: "",
    requirements: "",
  });
  const [showJoinModal, setShowJoinModal] = useState(false);
  const [selectedClub, setSelectedClub] = useState(null);
  const [joinFormData, setJoinFormData] = useState({
    fullName: "",
    department: "",
    year: "",
    background: "",
  });
  const [joinRequests, setJoinRequests] = useState([]);
  const [showJoinRequests, setShowJoinRequests] = useState(false);
  const [selectedClubDetails, setSelectedClubDetails] = useState(null);
  const [showClubDetails, setShowClubDetails] = useState(false);

  const categories = [
    "All",
    "Academic",
    "Sports",
    "Cultural",
    "Technology",
    "Service",
    "Arts",
    "Religious",
    "Professional",
  ];

  useEffect(() => {
    fetchClubs();
  }, []);

  const fetchClubs = async () => {
    try {
      setLoading(true);
      const response = await apiService.getClubs();
      console.log('Clubs API response:', response);
      
      // Handle different response structures
      let clubsData = [];
      if (Array.isArray(response)) {
        clubsData = response;
      } else if (response.clubs && Array.isArray(response.clubs)) {
        clubsData = response.clubs;
      } else if (response.data && Array.isArray(response.data)) {
        clubsData = response.data;
      } else if (response.success && response.clubs) {
        clubsData = response.clubs;
      }
      
      setClubs(clubsData);
    } catch (error) {
      console.error("Failed to fetch clubs:", error);
      toast.error("Failed to load clubs");
      setClubs([]);
    } finally {
      setLoading(false);
    }
  };

  const filteredClubs = clubs.filter((club) => {
    const matchesCategory =
      selectedCategory === "All" || club.category === selectedCategory;
    const matchesSearch =
      club.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      club.description.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesCategory && matchesSearch;
  });

  const handleJoinClub = (club) => {
    if (!user) {
      toast.error("Please login to join clubs");
      return;
    }
    
    if (user.isAdmin) {
      // Show club details for admin instead of join form
      setSelectedClubDetails(club);
      setShowClubDetails(true);
      return;
    }
    
    setSelectedClub(club);
    setJoinFormData({
      fullName: user.name || "",
      department: user.department || "",
      year: user.year || "",
      background: "",
    });
    setShowJoinModal(true);
  };

  const handleSubmitJoinRequest = async (e) => {
    e.preventDefault();

    if (!joinFormData.fullName || !joinFormData.department || !joinFormData.year) {
      toast.error("Please fill all required fields");
      return;
    }

    try {
      await apiService.joinClub(selectedClub._id || selectedClub.id, joinFormData);
      toast.success("Join request submitted successfully!");
      setShowJoinModal(false);
      setJoinFormData({
        fullName: "",
        department: "",
        year: "",
        background: "",
      });
    } catch (error) {
      console.error("Failed to join club:", error);
      toast.error(error.message || "Failed to submit join request");
    }
  };

  const fetchJoinRequests = async (clubId) => {
    try {
      const response = await apiService.getClubJoinRequests(clubId);
      setJoinRequests(response.requests || []);
      setSelectedClub(clubs.find(c => (c._id || c.id) === clubId));
      setShowJoinRequests(true);
    } catch (error) {
      console.error("Failed to fetch join requests:", error);
      toast.error("Failed to fetch join requests");
    }
  };

  const handleApproveRequest = async (clubId, memberId) => {
    try {
      await apiService.approveClubMember(clubId, memberId);
      toast.success("Member approved successfully!");
      await fetchJoinRequests(clubId);
      await fetchClubs(); // Refresh clubs to update member count
    } catch (error) {
      console.error("Failed to approve member:", error);
      toast.error("Failed to approve member");
    }
  };

  const handleRejectRequest = async (clubId, memberId) => {
    try {
      await apiService.rejectClubMember(clubId, memberId);
      toast.success("Member rejected successfully!");
      await fetchJoinRequests(clubId);
    } catch (error) {
      console.error("Failed to reject member:", error);
      toast.error("Failed to reject member");
    }
  };

  const handleImageUpload = (e) => {
    const file = e.target.files[0];
    if (file) {
      if (file.size > 5 * 1024 * 1024) { // 5MB limit
        toast.error("Image size must be less than 5MB");
        return;
      }
      
      const reader = new FileReader();
      reader.onload = (e) => {
        setNewClub({
          ...newClub,
          imageFile: file,
          imagePreview: e.target.result
        });
      };
      reader.readAsDataURL(file);
    }
  };

  const handleCreateClub = async (e) => {
    e.preventDefault();
    
    if (!user?.isAdmin) {
      toast.error("Only admins can create clubs");
      return;
    }

    if (!newClub.name.trim() || !newClub.description.trim()) {
      toast.error("Club name and description are required");
      return;
    }

    try {
      const clubData = {
        name: newClub.name.trim(),
        description: newClub.description.trim(),
        category: newClub.category,
        founded: new Date().getFullYear().toString(),
        image: newClub.imagePreview || "https://images.pexels.com/photos/3184291/pexels-photo-3184291.jpeg?auto=compress&cs=tinysrgb&w=400",
        contactEmail: newClub.contactEmail.trim(),
        contactPhone: newClub.contactPhone.trim(),
        website: newClub.website.trim(),
        officeLocation: newClub.officeLocation.trim(),
        meetingSchedule: newClub.meetingSchedule.trim(),
        requirements: newClub.requirements.trim(),
      };

      console.log('Creating club with data:', clubData);
      
      const response = await apiService.createClub(clubData);
      console.log('Create club response:', response);
      
      await fetchClubs(); // Refresh the clubs list
      toast.success("Club created successfully!");
      
      // Reset form
      setNewClub({
        name: "",
        category: "Academic",
        description: "",
        imageFile: null,
        imagePreview: "",
        contactEmail: "",
        contactPhone: "",
        website: "",
        officeLocation: "",
        meetingSchedule: "",
        requirements: "",
      });
      setShowNewClubForm(false);
    } catch (error) {
      console.error("Failed to create club:", error);
      toast.error(error.message || "Failed to create club");
    }
  };

  const handleDeleteClub = async (clubId) => {
    if (!user?.isAdmin) {
      toast.error("Only admins can delete clubs");
      return;
    }

    if (!confirm("Are you sure you want to delete this club?")) {
      return;
    }

    try {
      await apiService.deleteClub(clubId);
      await fetchClubs();
      toast.success("Club deleted successfully!");
    } catch (error) {
      console.error("Failed to delete club:", error);
      toast.error("Failed to delete club");
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <section className="bg-gradient-to-r from-blue-600 to-blue-800 text-white py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
            className="text-center">
            <h1 className="text-4xl md:text-6xl font-bold mb-6">
              Student Clubs
            </h1>
            <p className="text-xl md:text-2xl text-blue-100 max-w-4xl mx-auto">
              Join one of our many student clubs and organizations to pursue
              your interests, develop new skills, and connect with like-minded peers.
            </p>
          </motion.div>
        </div>
      </section>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Admin Controls */}
        {user?.isAdmin && (
          <div className="mb-8 bg-white rounded-xl p-6 shadow-sm">
            <div className="flex justify-between items-center">
              <h2 className="text-xl font-semibold text-gray-900">
                Admin Controls
              </h2>
              <button
                onClick={() => setShowNewClubForm(!showNewClubForm)}
                className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center">
                <Plus className="w-4 h-4 mr-2" />
                Create New Club
              </button>
            </div>

            {showNewClubForm && (
              <form onSubmit={handleCreateClub} className="mt-6 space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Club Name *
                    </label>
                    <input
                      type="text"
                      value={newClub.name}
                      onChange={(e) =>
                        setNewClub({ ...newClub, name: e.target.value })
                      }
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                      placeholder="Enter club name"
                      required
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Category *
                    </label>
                    <select
                      value={newClub.category}
                      onChange={(e) =>
                        setNewClub({ ...newClub, category: e.target.value })
                      }
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                      {categories.filter((cat) => cat !== "All").map((cat) => (
                        <option key={cat} value={cat}>
                          {cat}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Description *
                  </label>
                  <textarea
                    value={newClub.description}
                    onChange={(e) =>
                      setNewClub({ ...newClub, description: e.target.value })
                    }
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                    rows="3"
                    placeholder="Describe the club's purpose and activities"
                    required
                  />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Contact Email
                    </label>
                    <input
                      type="email"
                      value={newClub.contactEmail}
                      onChange={(e) =>
                        setNewClub({ ...newClub, contactEmail: e.target.value })
                      }
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                      placeholder="club@dbu.edu.et"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Contact Phone
                    </label>
                    <input
                      type="tel"
                      value={newClub.contactPhone}
                      onChange={(e) =>
                        setNewClub({ ...newClub, contactPhone: e.target.value })
                      }
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                      placeholder="+251-xxx-xxx-xxx"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Office Location
                    </label>
                    <input
                      type="text"
                      value={newClub.officeLocation}
                      onChange={(e) =>
                        setNewClub({ ...newClub, officeLocation: e.target.value })
                      }
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                      placeholder="Building and room number"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Website URL
                    </label>
                    <input
                      type="url"
                      value={newClub.website}
                      onChange={(e) =>
                        setNewClub({ ...newClub, website: e.target.value })
                      }
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                      placeholder="https://example.com"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Meeting Schedule
                  </label>
                  <input
                    type="text"
                    value={newClub.meetingSchedule}
                    onChange={(e) =>
                      setNewClub({ ...newClub, meetingSchedule: e.target.value })
                    }
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                    placeholder="e.g., Every Friday at 3:00 PM"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Membership Requirements
                  </label>
                  <textarea
                    value={newClub.requirements}
                    onChange={(e) =>
                      setNewClub({ ...newClub, requirements: e.target.value })
                    }
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                    rows="2"
                    placeholder="Any specific requirements for joining"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Club Image
                  </label>
                  <div className="space-y-2">
                    <input
                      type="file"
                      accept="image/*"
                      onChange={handleImageUpload}
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                    />
                    {newClub.imagePreview && (
                      <div className="mt-2">
                        <img
                          src={newClub.imagePreview}
                          alt="Preview"
                          className="w-32 h-32 object-cover rounded-lg border border-gray-300"
                        />
                      </div>
                    )}
                  </div>
                </div>

                <div className="flex gap-4">
                  <button
                    type="submit"
                    className="bg-green-600 text-white px-6 py-2 rounded-lg hover:bg-green-700 transition-colors">
                    Create Club
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowNewClubForm(false)}
                    className="bg-gray-600 text-white px-6 py-2 rounded-lg hover:bg-gray-700 transition-colors">
                    Cancel
                  </button>
                </div>
              </form>
            )}
          </div>
        )}

        {/* Search and Filter */}
        <div className="mb-8 lg:mb-12">
          {/* Search Bar */}
          <div className="relative mb-6">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
            <input
              type="text"
              placeholder="Search clubs..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>

          {/* Category Filter */}
          <div className="flex items-center gap-2 mb-6">
            <Filter className="w-5 h-5 text-gray-500" />
            <span className="text-gray-700 font-medium">Filter by category:</span>
          </div>

          <div className="flex flex-wrap gap-3">
            {categories.map((category) => (
              <button
                key={category}
                onClick={() => setSelectedCategory(category)}
                className={`px-4 py-2 rounded-full font-medium transition-colors ${
                  selectedCategory === category
                    ? "bg-blue-600 text-white"
                    : "bg-gray-200 text-gray-700 hover:bg-gray-300"
                }`}>
                {category}
              </button>
            ))}
          </div>
        </div>

        {/* Results Count */}
        {!loading && (
          <div className="mb-6">
            <p className="text-gray-600">
              Showing {filteredClubs.length} of {clubs.length} clubs
              {selectedCategory !== "All" && ` in ${selectedCategory}`}
              {searchTerm && ` matching "${searchTerm}"`}
            </p>
          </div>
        )}

        {/* Clubs Grid */}
        {loading ? (
          <div className="text-center py-8">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
            <p className="mt-4 text-gray-600">Loading clubs...</p>
          </div>
        ) : (
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6 lg:gap-8 mb-16">
            {filteredClubs.length > 0 ? (
              filteredClubs.map((club, index) => (
                <motion.div
                  key={club._id || club.id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: index * 0.1 }}
                  className="bg-white rounded-xl overflow-hidden shadow-sm hover:shadow-lg transition-shadow">
                  
                  <div className="relative">
                    <img
                      src={club.image || "https://images.pexels.com/photos/3184291/pexels-photo-3184291.jpeg?auto=compress&cs=tinysrgb&w=400"}
                      alt={club.name}
                      className="w-full h-48 object-cover"
                    />
                    <div className="absolute top-4 left-4">
                      <span className="bg-blue-600 text-white text-xs px-3 py-1 rounded-full font-medium">
                        {club.category}
                      </span>
                    </div>
                    {user?.isAdmin && (
                      <div className="absolute top-4 right-4 flex space-x-2">
                        <button
                          onClick={() => fetchJoinRequests(club._id || club.id)}
                          className="bg-blue-600 text-white p-2 rounded-full hover:bg-blue-700 transition-colors"
                          title="View Join Requests">
                          <Users className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => {
                            setSelectedClubDetails(club);
                            setShowClubDetails(true);
                          }}
                          className="bg-green-600 text-white p-2 rounded-full hover:bg-green-700 transition-colors"
                          title="View Members">
                          👥
                        </button>
                        <button
                          onClick={() => handleDeleteClub(club._id || club.id)}
                          className="bg-red-600 text-white p-2 rounded-full hover:bg-red-700 transition-colors"
                          title="Delete Club">
                          ✕
                        </button>
                      </div>
                    )}
                  </div>

                  <div className="p-6">
                    <div className="flex items-center justify-between mb-3">
                      <h3 className="text-xl font-semibold text-gray-900">
                        {club.name}
                      </h3>
                      <span className="text-gray-500 text-sm">
                        Est. {club.founded}
                      </span>
                    </div>

                    <p className="text-gray-600 mb-4 text-sm leading-relaxed">
                      {club.description}
                    </p>

                    {/* Contact Info */}
                    {(club.contactEmail || club.contactPhone || club.officeLocation || club.website) && (
                      <div className="mb-4 p-3 bg-gray-50 rounded-lg">
                        <h4 className="font-medium text-gray-900 mb-2">Contact Information</h4>
                        <div className="space-y-1">
                          {club.officeLocation && (
                            <div className="flex items-center text-sm text-gray-600">
                              <MapPin className="w-4 h-4 mr-2" />
                              <span>{club.officeLocation}</span>
                            </div>
                          )}
                          {club.contactEmail && (
                            <div className="flex items-center text-sm text-gray-600">
                              <Mail className="w-4 h-4 mr-2" />
                              <span>{club.contactEmail}</span>
                            </div>
                          )}
                          {club.contactPhone && (
                            <div className="flex items-center text-sm text-gray-600">
                              <Phone className="w-4 h-4 mr-2" />
                              <span>{club.contactPhone}</span>
                            </div>
                          )}
                          {club.website && (
                            <div className="flex items-center text-sm text-gray-600">
                              <Globe className="w-4 h-4 mr-2" />
                              <a href={club.website} target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">
                                Visit Website
                              </a>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Meeting Schedule */}
                    {club.meetingSchedule && (
                      <div className="mb-4 p-3 bg-blue-50 rounded-lg">
                        <h4 className="font-medium text-blue-900 mb-1">Meeting Schedule</h4>
                        <p className="text-sm text-blue-800">{club.meetingSchedule}</p>
                      </div>
                    )}

                    {/* Stats */}
                    <div className="flex items-center justify-between text-sm text-gray-500 mb-4">
                      <div className="flex items-center">
                        <Users className="w-4 h-4 mr-1" />
                        <span>{club.members || 0} members</span>
                      </div>
                      <div className="flex items-center">
                        <Calendar className="w-4 h-4 mr-1" />
                        <span>{club.events || 0} events</span>
                      </div>
                    </div>

                    <button
                      onClick={() => handleJoinClub(club)}
                      className={`w-full py-2 px-4 rounded-lg font-medium transition-colors ${
                        user?.isAdmin 
                          ? "bg-green-600 text-white hover:bg-green-700" 
                          : "bg-blue-600 text-white hover:bg-blue-700"
                      }`}>
                      {user?.isAdmin ? "Manage Club" : "Join Club"}
                    </button>
                  </div>
                </motion.div>
              ))
            ) : (
              <div className="col-span-full text-center py-12">
                <div className="w-16 h-16 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Search className="w-8 h-8 text-gray-400" />
                </div>
                <h3 className="text-xl font-semibold text-gray-900 mb-2">
                  No clubs found
                </h3>
                <p className="text-gray-600 mb-4">
                  Try adjusting your search terms or category filter
                </p>
                <button
                  onClick={() => {
                    setSearchTerm("");
                    setSelectedCategory("All");
                  }}
                  className="text-blue-600 hover:text-blue-700 font-medium">
                  Clear filters
                </button>
              </div>
            )}
          </div>
        )}

        {/* Join Club Modal */}
        {showJoinModal && selectedClub && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
            <div className="bg-white rounded-2xl max-w-md w-full max-h-[90vh] overflow-y-auto">
              <div className="p-6">
                <div className="flex items-center justify-between mb-6">
                  <h2 className="text-xl font-bold text-gray-900">
                    Join {selectedClub.name}
                  </h2>
                  <button
                    onClick={() => setShowJoinModal(false)}
                    className="text-gray-400 hover:text-gray-600">
                    ✕
                  </button>
                </div>

                <form onSubmit={handleSubmitJoinRequest} className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Full Name *
                    </label>
                    <input
                      type="text"
                      required
                      value={joinFormData.fullName}
                      onChange={(e) =>
                        setJoinFormData({ ...joinFormData, fullName: e.target.value })
                      }
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                      placeholder="Your full name"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Department *
                    </label>
                    <select
                      required
                      value={joinFormData.department}
                      onChange={(e) =>
                        setJoinFormData({ ...joinFormData, department: e.target.value })
                      }
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                      <option value="">Select Department</option>
                      <option value="Computer Science">Computer Science</option>
                      <option value="Engineering">Engineering</option>
                      <option value="Business">Business</option>
                      <option value="Medicine">Medicine</option>
                      <option value="Agriculture">Agriculture</option>
                      <option value="Education">Education</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Academic Year *
                    </label>
                    <select
                      required
                      value={joinFormData.year}
                      onChange={(e) =>
                        setJoinFormData({ ...joinFormData, year: e.target.value })
                      }
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                      <option value="">Select Year</option>
                      <option value="1st Year">1st Year</option>
                      <option value="2nd Year">2nd Year</option>
                      <option value="3rd Year">3rd Year</option>
                      <option value="4th Year">4th Year</option>
                      <option value="5th Year">5th Year</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Why do you want to join this club?
                    </label>
                    <textarea
                      value={joinFormData.background}
                      onChange={(e) =>
                        setJoinFormData({ ...joinFormData, background: e.target.value })
                      }
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                      rows="3"
                      placeholder="Tell us about your background and motivation"
                    />
                  </div>

                  <div className="flex gap-4">
                    <button
                      type="button"
                      onClick={() => setShowJoinModal(false)}
                      className="flex-1 bg-gray-600 text-white px-4 py-2 rounded-lg hover:bg-gray-700 transition-colors">
                      Cancel
                    </button>
                    <button
                      type="submit"
                      className="flex-1 bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors">
                      Submit Request
                    </button>
                  </div>
                </form>
              </div>
            </div>
          </div>
        )}

        {/* Club Details Modal for Admin */}
        {showClubDetails && selectedClubDetails && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
            <div className="bg-white rounded-2xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
              <div className="p-6">
                <div className="flex items-center justify-between mb-6">
                  <h2 className="text-xl font-bold text-gray-900">
                    {selectedClubDetails.name} - Members
                  </h2>
                  <button
                    onClick={() => setShowClubDetails(false)}
                    className="text-gray-400 hover:text-gray-600">
                    ✕
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <h3 className="font-semibold text-gray-900 mb-3">Club Information</h3>
                    <div className="space-y-2 text-sm">
                      <p><span className="font-medium">Category:</span> {selectedClubDetails.category}</p>
                      <p><span className="font-medium">Founded:</span> {selectedClubDetails.founded}</p>
                      <p><span className="font-medium">Total Members:</span> {selectedClubDetails.members || 0}</p>
                      <p><span className="font-medium">Status:</span> {selectedClubDetails.status}</p>
                    </div>
                  </div>
                  
                  <div>
                    <h3 className="font-semibold text-gray-900 mb-3">Contact Information</h3>
                    <div className="space-y-2 text-sm">
                      {selectedClubDetails.contactEmail && (
                        <p><span className="font-medium">Email:</span> {selectedClubDetails.contactEmail}</p>
                      )}
                      {selectedClubDetails.contactPhone && (
                        <p><span className="font-medium">Phone:</span> {selectedClubDetails.contactPhone}</p>
                      )}
                      {selectedClubDetails.officeLocation && (
                        <p><span className="font-medium">Office:</span> {selectedClubDetails.officeLocation}</p>
                      )}
                    </div>
                  </div>
                </div>

                <div className="mt-6">
                  <h3 className="font-semibold text-gray-900 mb-3">Description</h3>
                  <p className="text-gray-600 text-sm">{selectedClubDetails.description}</p>
                </div>

                <div className="mt-6 flex justify-center">
                  <button
                    onClick={() => fetchJoinRequests(selectedClubDetails._id || selectedClubDetails.id)}
                    className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors">
                    View Join Requests
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Join Requests Modal */}
        {showJoinRequests && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
            <div className="bg-white rounded-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
              <div className="p-6">
                <div className="flex items-center justify-between mb-6">
                  <h2 className="text-xl font-bold text-gray-900">
                    Join Requests - {selectedClub?.name}
                  </h2>
                  <button
                    onClick={() => setShowJoinRequests(false)}
                    className="text-gray-400 hover:text-gray-600">
                    ✕
                  </button>
                </div>
                
                <div className="space-y-4">
                  {joinRequests.length === 0 ? (
                    <p className="text-gray-600 text-center py-8">
                      No pending join requests
                    </p>
                  ) : (
                    joinRequests.map((request) => (
                      <div
                        key={request._id}
                        className="border border-gray-200 rounded-lg p-4">
                        <div className="flex justify-between items-start mb-3">
                          <div>
                            <h3 className="font-semibold text-gray-900">
                              {request.fullName}
                            </h3>
                            <p className="text-sm text-gray-600">
                              {request.department} - {request.year}
                            </p>
                            {request.user?.username && (
                              <p className="text-sm text-gray-600">
                                Username: {request.user.username}
                              </p>
                            )}
                            <p className="text-xs text-gray-500">
                              Applied: {new Date(request.joinedAt).toLocaleDateString()}
                            </p>
                          </div>
                          <div className="flex gap-2">
                            <button
                              onClick={() =>
                                handleApproveRequest(selectedClub._id || selectedClub.id, request._id)
                              }
                              className="bg-green-600 text-white px-3 py-1 rounded text-sm hover:bg-green-700 transition-colors">
                              Approve
                            </button>
                            <button
                              onClick={() =>
                                handleRejectRequest(selectedClub._id || selectedClub.id, request._id)
                              }
                              className="bg-red-600 text-white px-3 py-1 rounded text-sm hover:bg-red-700 transition-colors">
                              Reject
                            </button>
                          </div>
                        </div>
                        {request.background && (
                          <div>
                            <p className="text-sm font-medium text-gray-700 mb-1">
                              Background:
                            </p>
                            <p className="text-sm text-gray-600">{request.background}</p>
                          </div>
                        )}
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Create Club CTA */}
        <div className="bg-gradient-to-r from-green-600 to-green-800 rounded-2xl p-6 lg:p-8 text-center text-white">
          <div className="max-w-2xl mx-auto">
            <div className="w-16 h-16 bg-white bg-opacity-20 rounded-full flex items-center justify-center mx-auto mb-4">
              <Plus className="w-8 h-8" />
            </div>
            <h2 className="text-2xl lg:text-3xl font-bold mb-4">
              Want to Start a New Club?
            </h2>
            <p className="text-green-100 mb-6 text-lg">
              Have an idea for a new club or organization? We support student
              initiatives and can help you get started with the registration process.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <button 
                onClick={() => user?.isAdmin ? setShowNewClubForm(true) : toast.info("Contact an admin to start a new club")}
                className="bg-white text-green-600 px-6 py-3 rounded-lg font-semibold hover:bg-gray-100 transition-colors">
                Start a Club
              </button>
              <button className="border-2 border-white text-white px-6 py-3 rounded-lg font-semibold hover:bg-white hover:text-green-600 transition-colors">
                Learn More
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}