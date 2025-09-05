import React, { useState, useEffect } from "react";
import {
  Vote,
  Users,
  Clock,
  CheckCircle,
  Calendar,
  Eye,
  BarChart3,
  Plus,
  Trash2,
  User,
} from "lucide-react";
import { motion } from "framer-motion";
import { useAuth } from "../../contexts/AuthContext";
import { apiService } from "../../services/api";
import toast from "react-hot-toast";

export function Elections() {
  const { user } = useAuth();
  const [selectedTab, setSelectedTab] = useState("all");
  const [selectedElection, setSelectedElection] = useState(null);
  const [elections, setElections] = useState([]);
  const [loading, setLoading] = useState(true);
  const [votedElections, setVotedElections] = useState(new Set());
  const [showNewElectionForm, setShowNewElectionForm] = useState(false);
  const [votingInProgress, setVotingInProgress] = useState(false);
  const [newElection, setNewElection] = useState({
    title: "",
    description: "",
    startDate: "",
    endDate: "",
    electionType: "general",
    isPublic: true,
    candidates: [],
  });
  const [newCandidate, setNewCandidate] = useState({
    name: "",
    username: "",
    department: "",
    year: "",
    academicYear: "",
    position: "President",
    profileImageFile: null,
    profileImagePreview: "",
    platform: "",
    biography: "",
  });

  useEffect(() => {
    fetchElections();
  }, []);

  const fetchElections = async () => {
    try {
      setLoading(true);
      const response = await apiService.getElections();
      console.log('Elections API response:', response);
      
      // Handle different response structures
      let electionsData = [];
      if (Array.isArray(response)) {
        electionsData = response;
      } else if (response.elections && Array.isArray(response.elections)) {
        electionsData = response.elections;
      } else if (response.data && Array.isArray(response.data)) {
        electionsData = response.data;
      } else if (response.success && response.elections) {
        electionsData = response.elections;
      }
      
      setElections(electionsData);
    } catch (error) {
      console.error("Failed to fetch elections:", error);
      toast.error("Failed to load elections");
      setElections([]);
    } finally {
      setLoading(false);
    }
  };

  const handleCandidateImageUpload = (e) => {
    const file = e.target.files[0];
    if (file) {
      if (file.size > 5 * 1024 * 1024) { // 5MB limit
        toast.error("Image size must be less than 5MB");
        return;
      }
      
      const reader = new FileReader();
      reader.onload = (e) => {
        setNewCandidate({
          ...newCandidate,
          profileImageFile: file,
          profileImagePreview: e.target.result
        });
      };
      reader.readAsDataURL(file);
    }
  };

  const handleAddCandidate = (e) => {
    e.preventDefault();
    
    if (!newCandidate.name || !newCandidate.department || !newCandidate.academicYear) {
      toast.error("Candidate name, department, and academic year are required");
      return;
    }

    const candidate = {
      name: newCandidate.name.trim(),
      username: newCandidate.username.trim() || `dbu${Date.now().toString().slice(-8)}`,
      department: newCandidate.department,
      year: newCandidate.year || newCandidate.academicYear,
      academicYear: newCandidate.academicYear,
      position: newCandidate.position,
      profileImage: newCandidate.profileImagePreview || "https://images.pexels.com/photos/3763188/pexels-photo-3763188.jpeg?auto=compress&cs=tinysrgb&w=400",
      platform: newCandidate.platform ? newCandidate.platform.split(',').map(p => p.trim()) : ["Student Welfare", "Academic Excellence"],
      biography: newCandidate.biography || `Candidate for ${newCandidate.position}`,
      votes: 0,
      voters: []
    };

    setNewElection(prev => ({
      ...prev,
      candidates: [...prev.candidates, candidate],
    }));

    // Reset candidate form
    setNewCandidate({
      name: "",
      username: "",
      department: "",
      year: "",
      academicYear: "",
      position: "President",
      profileImageFile: null,
      profileImagePreview: "",
      platform: "",
      biography: "",
    });

    toast.success("Candidate added successfully!");
  };

  const handleRemoveCandidate = (index) => {
    setNewElection(prev => ({
      ...prev,
      candidates: prev.candidates.filter((_, i) => i !== index),
    }));
  };

  const handleCreateElection = async (e) => {
    e.preventDefault();
    
    if (!user?.isAdmin) {
      toast.error("Only admins can create elections");
      return;
    }

    if (!newElection.title.trim() || !newElection.description.trim()) {
      toast.error("Title and description are required");
      return;
    }

    if (!newElection.startDate || !newElection.endDate) {
      toast.error("Start date and end date are required");
      return;
    }

    if (new Date(newElection.startDate) >= new Date(newElection.endDate)) {
      toast.error("End date must be after start date");
      return;
    }

    if (newElection.candidates.length < 2) {
      toast.error("At least two candidates are required");
      return;
    }

    try {
      const electionData = {
        title: newElection.title.trim(),
        description: newElection.description.trim(),
        startDate: newElection.startDate,
        endDate: newElection.endDate,
        electionType: newElection.electionType,
        isPublic: newElection.isPublic,
        candidates: newElection.candidates,
        rules: ["One vote per student", "Valid student ID required", "Voting is anonymous"],
      };

      console.log('Creating election with data:', electionData);
      
      const response = await apiService.createElection(electionData);
      console.log('Create election response:', response);
      
      await fetchElections();
      toast.success("Election created successfully!");
      
      // Reset form
      setNewElection({
        title: "",
        description: "",
        startDate: "",
        endDate: "",
        electionType: "general",
        isPublic: true,
        candidates: [],
      });
      setShowNewElectionForm(false);
    } catch (error) {
      console.error("Failed to create election:", error);
      toast.error(error.message || "Failed to create election");
    }
  };

  const handleVote = async (electionId, candidateId) => {
    if (!user) {
      toast.error("Please login to vote");
      return;
    }

    if (user.isAdmin) {
      toast.error("Admins cannot vote in elections");
      return;
    }

    if (votedElections.has(electionId)) {
      toast.error("You have already voted in this election");
      return;
    }

    if (votingInProgress) {
      return; // Prevent multiple votes while processing
    }

    try {
      setVotingInProgress(true);
      await apiService.voteInElection(electionId, candidateId);
      setVotedElections(new Set([...votedElections, electionId]));
      await fetchElections();
      toast.success("Vote cast successfully!");
      setSelectedElection(null);
    } catch (error) {
      console.error("Failed to vote:", error);
      toast.error(error.message || "Failed to cast vote");
    } finally {
      setVotingInProgress(false);
    }
  };

  const handleDeleteElection = async (electionId) => {
    if (!user?.isAdmin) {
      toast.error("Only admins can delete elections");
      return;
    }

    if (!confirm("Are you sure you want to delete this election?")) {
      return;
    }

    try {
      await apiService.deleteElection(electionId);
      await fetchElections();
      toast.success("Election deleted successfully!");
    } catch (error) {
      console.error("Failed to delete election:", error);
      toast.error("Failed to delete election");
    }
  };

  const announceResults = async (electionId) => {
    if (!user?.isAdmin) {
      toast.error("Only admins can announce results");
      return;
    }

    try {
      await apiService.announceElectionResults(electionId);
      toast.success("Election results announced!");
      await fetchElections();
    } catch (error) {
      console.error("Failed to announce results:", error);
      toast.error("Failed to announce results");
    }
  };

  const filteredElections = elections.filter((election) => {
    if (selectedTab === "all") return true;
    return election.status === selectedTab;
  });

  const getStatusColor = (status) => {
    switch (status) {
      case "active":
        return "bg-green-100 text-green-800";
      case "upcoming":
        return "bg-blue-100 text-blue-800";
      case "completed":
        return "bg-gray-100 text-gray-800";
      default:
        return "bg-gray-100 text-gray-800";
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case "active":
        return <Vote className="w-4 h-4" />;
      case "upcoming":
        return <Clock className="w-4 h-4" />;
      case "completed":
        return <CheckCircle className="w-4 h-4" />;
      default:
        return <Calendar className="w-4 h-4" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gradient-to-r from-blue-600 to-blue-800 text-white py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
            className="text-center">
            <h1 className="text-4xl md:text-6xl font-bold mb-6">
              Student Elections
            </h1>
            <p className="text-xl md:text-2xl text-blue-100 max-w-4xl mx-auto">
              Vote for your future student union leaders for Debre Berhan University
            </p>
          </motion.div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Admin Controls */}
        {user?.isAdmin && (
          <div className="mb-8 bg-white rounded-xl p-6 shadow-sm">
            <div className="flex justify-between items-center">
              <h2 className="text-xl font-semibold text-gray-900">
                Admin Controls
              </h2>
              <button
                onClick={() => setShowNewElectionForm(!showNewElectionForm)}
                className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center">
                <Plus className="w-4 h-4 mr-2" />
                Create New Election
              </button>
            </div>

            {showNewElectionForm && (
              <div className="mt-6 space-y-6">
                <form onSubmit={handleCreateElection} className="space-y-4">
                  {/* Basic Election Info */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">
                        Election Title *
                      </label>
                      <input
                        type="text"
                        value={newElection.title}
                        onChange={(e) =>
                          setNewElection({ ...newElection, title: e.target.value })
                        }
                        className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                        placeholder="e.g., Student Union President Election 2024"
                        required
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">
                        Election Type
                      </label>
                      <select
                        value={newElection.electionType}
                        onChange={(e) =>
                          setNewElection({ ...newElection, electionType: e.target.value })
                        }
                        className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                        <option value="general">General</option>
                        <option value="president">President</option>
                        <option value="vice_president">Vice President</option>
                        <option value="secretary">Secretary</option>
                        <option value="treasurer">Treasurer</option>
                      </select>
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Description *
                    </label>
                    <textarea
                      value={newElection.description}
                      onChange={(e) =>
                        setNewElection({ ...newElection, description: e.target.value })
                      }
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                      rows="3"
                      placeholder="Describe the election purpose and details"
                      required
                    />
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">
                        Start Date *
                      </label>
                      <input
                        type="datetime-local"
                        value={newElection.startDate}
                        onChange={(e) =>
                          setNewElection({ ...newElection, startDate: e.target.value })
                        }
                        className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                        required
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">
                        End Date *
                      </label>
                      <input
                        type="datetime-local"
                        value={newElection.endDate}
                        onChange={(e) =>
                          setNewElection({ ...newElection, endDate: e.target.value })
                        }
                        className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                        required
                      />
                    </div>
                  </div>

                  <div className="flex items-center">
                    <input
                      type="checkbox"
                      id="isPublic"
                      checked={newElection.isPublic}
                      onChange={(e) =>
                        setNewElection({ ...newElection, isPublic: e.target.checked })
                      }
                      className="h-4 w-4 text-blue-600 rounded focus:ring-blue-500"
                    />
                    <label htmlFor="isPublic" className="ml-2 text-sm text-gray-700">
                      Make this election public
                    </label>
                  </div>
                </form>

                {/* Candidates Section */}
                <div className="border-t pt-6">
                  <h3 className="text-lg font-medium text-gray-900 mb-4">
                    Add Candidates ({newElection.candidates.length})
                  </h3>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Candidate Name *
                      </label>
                      <input
                        type="text"
                        value={newCandidate.name}
                        onChange={(e) =>
                          setNewCandidate({ ...newCandidate, name: e.target.value })
                        }
                        className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                        placeholder="Full name"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Username
                      </label>
                      <input
                        type="text"
                        value={newCandidate.username}
                        onChange={(e) =>
                          setNewCandidate({ ...newCandidate, username: e.target.value })
                        }
                        className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                        placeholder="dbu12345678"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Department *
                      </label>
                      <select
                        value={newCandidate.department}
                        onChange={(e) =>
                          setNewCandidate({ ...newCandidate, department: e.target.value })
                        }
                        className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
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
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Academic Year *
                      </label>
                      <select
                        value={newCandidate.academicYear}
                        onChange={(e) =>
                          setNewCandidate({ 
                            ...newCandidate, 
                            academicYear: e.target.value,
                            year: e.target.value 
                          })
                        }
                        className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                        <option value="">Select Year</option>
                        <option value="1st Year">1st Year</option>
                        <option value="2nd Year">2nd Year</option>
                        <option value="3rd Year">3rd Year</option>
                        <option value="4th Year">4th Year</option>
                        <option value="5th Year">5th Year</option>
                      </select>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Position
                      </label>
                      <select
                        value={newCandidate.position}
                        onChange={(e) =>
                          setNewCandidate({ ...newCandidate, position: e.target.value })
                        }
                        className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                        <option value="President">President</option>
                        <option value="Vice President">Vice President</option>
                        <option value="Secretary">Secretary</option>
                        <option value="Treasurer">Treasurer</option>
                      </select>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Profile Image
                      </label>
                      <div className="space-y-2">
                        <input
                          type="file"
                          accept="image/*"
                          onChange={handleCandidateImageUpload}
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                        />
                        {newCandidate.profileImagePreview && (
                          <div className="mt-2">
                            <img
                              src={newCandidate.profileImagePreview}
                              alt="Preview"
                              className="w-16 h-16 object-cover rounded-full border border-gray-300"
                            />
                          </div>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Platform (comma-separated)
                      </label>
                      <input
                        type="text"
                        value={newCandidate.platform}
                        onChange={(e) =>
                          setNewCandidate({ ...newCandidate, platform: e.target.value })
                        }
                        className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                        placeholder="Student Welfare, Academic Excellence, Campus Infrastructure"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Biography
                      </label>
                      <textarea
                        value={newCandidate.biography}
                        onChange={(e) =>
                          setNewCandidate({ ...newCandidate, biography: e.target.value })
                        }
                        className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                        rows="2"
                        placeholder="Brief biography of the candidate"
                      />
                    </div>
                  </div>

                  <div className="flex justify-end mb-4">
                    <button
                      type="button"
                      onClick={handleAddCandidate}
                      className="bg-green-600 text-white px-4 py-2 rounded-lg hover:bg-green-700 transition-colors">
                      Add Candidate
                    </button>
                  </div>

                  {/* Candidates List */}
                  {newElection.candidates.length > 0 && (
                    <div className="space-y-2 mb-4">
                      <h4 className="font-medium text-gray-900">Added Candidates:</h4>
                      {newElection.candidates.map((candidate, index) => (
                        <div key={index} className="flex items-center justify-between bg-gray-50 p-3 rounded-lg">
                          <div>
                            <span className="font-medium">{candidate.name}</span>
                            <span className="text-gray-600 ml-2">
                              ({candidate.department} - {candidate.academicYear})
                            </span>
                          </div>
                          <button
                            type="button"
                            onClick={() => handleRemoveCandidate(index)}
                            className="text-red-600 hover:text-red-700">
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Form Actions */}
                  <div className="flex gap-4 pt-4 border-t">
                    <button
                      type="button"
                      onClick={handleCreateElection}
                      className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors">
                      Create Election
                    </button>
                    <button
                      type="button"
                      onClick={() => setShowNewElectionForm(false)}
                      className="bg-gray-600 text-white px-6 py-2 rounded-lg hover:bg-gray-700 transition-colors">
                      Cancel
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Filter Tabs */}
        <div className="border-b border-gray-200 mb-8">
          <nav className="-mb-px flex space-x-8">
            {["all", "active", "upcoming", "completed"].map((tab) => (
              <button
                key={tab}
                onClick={() => setSelectedTab(tab)}
                className={`py-2 px-1 border-b-2 font-medium text-sm transition-colors ${
                  selectedTab === tab
                    ? "border-blue-500 text-blue-600"
                    : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300"
                }`}>
                {tab.charAt(0).toUpperCase() + tab.slice(1)}
              </button>
            ))}
          </nav>
        </div>

        {/* Elections List */}
        {loading ? (
          <div className="text-center py-8">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
            <p className="mt-4 text-gray-600">Loading elections...</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {filteredElections.length > 0 ? (
              filteredElections.map((election, index) => (
                <motion.div
                  key={election._id || election.id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: index * 0.1 }}
                  className="bg-white rounded-xl p-6 shadow-sm border border-gray-100 hover:shadow-md transition-shadow">
                  
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex-1">
                      <h3 className="text-lg font-semibold text-gray-900 mb-2">
                        {election.title}
                      </h3>
                      <p className="text-gray-600 text-sm mb-3">
                        {election.description}
                      </p>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span
                        className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(
                          election.status
                        )}`}>
                        {getStatusIcon(election.status)}
                        <span className="ml-1 capitalize">{election.status}</span>
                      </span>
                      {user?.isAdmin && (
                        <button
                          onClick={() => handleDeleteElection(election._id || election.id)}
                          className="text-red-600 hover:text-red-700 p-1">
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Election Stats */}
                  <div className="grid grid-cols-2 gap-4 mb-4">
                    <div className="bg-gray-50 rounded-lg p-3">
                      <div className="flex items-center space-x-2">
                        <Users className="w-4 h-4 text-gray-500" />
                        <span className="text-sm font-medium text-gray-900">Votes</span>
                      </div>
                      <p className="text-lg font-bold text-gray-900 mt-1">
                        {(election.totalVotes || 0).toLocaleString()}
                      </p>
                      <p className="text-xs text-gray-500">
                        of {(election.eligibleVoters || 0).toLocaleString()} eligible
                      </p>
                    </div>

                    <div className="bg-gray-50 rounded-lg p-3">
                      <div className="flex items-center space-x-2">
                        <Calendar className="w-4 h-4 text-gray-500" />
                        <span className="text-sm font-medium text-gray-900">Period</span>
                      </div>
                      <p className="text-sm font-bold text-gray-900 mt-1">
                        {new Date(election.startDate).toLocaleDateString()}
                      </p>
                      <p className="text-xs text-gray-500">
                        to {new Date(election.endDate).toLocaleDateString()}
                      </p>
                    </div>
                  </div>

                  {/* Candidates Preview */}
                  {election.candidates && election.candidates.length > 0 && (
                    <div className="mb-4">
                      <h4 className="text-sm font-medium text-gray-900 mb-3">
                        Candidates ({election.candidates.length})
                      </h4>
                      <div className="flex -space-x-2 overflow-hidden">
                        {election.candidates.slice(0, 5).map((candidate, idx) => (
                          <img
                            key={idx}
                            src={candidate.profileImage || "https://images.pexels.com/photos/3763188/pexels-photo-3763188.jpeg?auto=compress&cs=tinysrgb&w=400"}
                            alt={candidate.name}
                            className="w-8 h-8 rounded-full border-2 border-white object-cover"
                          />
                        ))}
                        {election.candidates.length > 5 && (
                          <div className="w-8 h-8 rounded-full border-2 border-white bg-gray-100 flex items-center justify-center">
                            <span className="text-xs text-gray-600">+{election.candidates.length - 5}</span>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Actions */}
                  <div className="flex space-x-3">
                    {election.status === "active" && (
                      <motion.button
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.98 }}
                        onClick={() => setSelectedElection(election)}
                        className="flex-1 bg-blue-600 text-white py-2 px-4 rounded-lg font-medium hover:bg-blue-700 transition-colors"
                        disabled={votedElections.has(election._id || election.id)}>
                        <Vote className="w-4 h-4 inline mr-2" />
                        {votedElections.has(election._id || election.id) ? "Voted" : "Vote Now"}
                      </motion.button>
                    )}

                    <motion.button
                      whileHover={{ scale: 1.02 }}
                      whileTap={{ scale: 0.98 }}
                      onClick={() => setSelectedElection(election)}
                      className="flex-1 bg-gray-100 text-gray-700 py-2 px-4 rounded-lg font-medium hover:bg-gray-200 transition-colors">
                      <Eye className="w-4 h-4 inline mr-2" />
                      View Details
                    </motion.button>

                    {election.status === "completed" && user?.isAdmin && !election.resultsPublished && (
                      <button
                        onClick={() => announceResults(election._id || election.id)}
                        className="bg-yellow-600 text-white py-2 px-4 rounded-lg font-medium hover:bg-yellow-700 transition-colors">
                        Announce Results
                      </button>
                    )}
                  </div>
                </motion.div>
              ))
            ) : (
              <div className="col-span-2 text-center py-12">
                <div className="w-16 h-16 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Vote className="w-8 h-8 text-gray-400" />
                </div>
                <h3 className="text-xl font-semibold text-gray-900 mb-2">
                  No elections found
                </h3>
                <p className="text-gray-600">
                  {selectedTab === "all" 
                    ? "No elections have been created yet"
                    : `No ${selectedTab} elections at this time`
                  }
                </p>
              </div>
            )}
          </div>
        )}

        {/* Voting Modal */}
        {selectedElection && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              className="bg-white rounded-2xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
              <div className="p-6">
                <div className="flex items-center justify-between mb-6">
                  <h2 className="text-xl font-bold text-gray-900">
                    {selectedElection.title}
                  </h2>
                  <button
                    onClick={() => setSelectedElection(null)}
                    className="text-gray-400 hover:text-gray-600">
                    ✕
                  </button>
                </div>

                <p className="text-gray-600 mb-6">{selectedElection.description}</p>

                {/* Election Info */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6 p-4 bg-gray-50 rounded-lg">
                  <div className="text-center">
                    <p className="text-sm text-gray-600">Total Votes</p>
                    <p className="text-2xl font-bold text-blue-600">{selectedElection.totalVotes || 0}</p>
                  </div>
                  <div className="text-center">
                    <p className="text-sm text-gray-600">Candidates</p>
                    <p className="text-2xl font-bold text-green-600">{selectedElection.candidates?.length || 0}</p>
                  </div>
                  <div className="text-center">
                    <p className="text-sm text-gray-600">Status</p>
                    <p className="text-lg font-bold text-gray-900 capitalize">{selectedElection.status}</p>
                  </div>
                </div>

                {votedElections.has(selectedElection._id || selectedElection.id) && (
                  <div className="mb-6 p-4 bg-green-50 border border-green-200 rounded-lg">
                    <p className="text-green-800 font-medium flex items-center">
                      <CheckCircle className="w-5 h-5 mr-2" />
                      You have already voted in this election
                    </p>
                  </div>
                )}

                {/* Candidates */}
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold text-gray-900">Candidates</h3>
                  {selectedElection.candidates && selectedElection.candidates.length > 0 ? (
                    selectedElection.candidates.map((candidate, index) => (
                      <div
                        key={candidate._id || candidate.id || index}
                        className="border border-gray-200 rounded-lg p-4 hover:border-blue-300 transition-colors">
                        <div className="flex items-start space-x-4">
                          <img
                            src={candidate.profileImage || "https://images.pexels.com/photos/3763188/pexels-photo-3763188.jpeg?auto=compress&cs=tinysrgb&w=400"}
                            alt={candidate.name}
                            className="w-16 h-16 rounded-full object-cover"
                          />
                          <div className="flex-1">
                            <h4 className="text-lg font-semibold text-gray-900">
                              {candidate.name}
                            </h4>
                            <p className="text-gray-600">
                              {candidate.department} - {candidate.academicYear || candidate.year}
                            </p>
                            <p className="text-sm text-gray-500 mb-2">{candidate.position}</p>
                            
                            {candidate.platform && candidate.platform.length > 0 && (
                              <div className="mt-2">
                                <p className="text-sm font-medium text-gray-700 mb-1">Platform:</p>
                                <div className="flex flex-wrap gap-1">
                                  {candidate.platform.map((item, idx) => (
                                    <span
                                      key={idx}
                                      className="inline-block bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded">
                                      {item}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            )}

                            {candidate.biography && (
                              <p className="text-sm text-gray-600 mt-2">{candidate.biography}</p>
                            )}
                          </div>
                          
                          <div className="text-right">
                            <p className="text-2xl font-bold text-gray-900">
                              {(candidate.votes || 0).toLocaleString()}
                            </p>
                            <p className="text-sm text-gray-500">votes</p>
                            {user?.isAdmin && selectedElection.totalVotes > 0 && (
                              <p className="text-xs text-gray-400 mt-1">
                                {((candidate.votes || 0) / Math.max(selectedElection.totalVotes, 1) * 100).toFixed(1)}%
                              </p>
                            )}
                          </div>
                        </div>
                        
                        {selectedElection.status === "active" && 
                         !votedElections.has(selectedElection._id || selectedElection.id) && 
                         !user?.isAdmin && (
                          <motion.button
                            whileHover={{ scale: 1.02 }}
                            whileTap={{ scale: 0.98 }}
                            onClick={() =>
                              handleVote(selectedElection._id || selectedElection.id, candidate._id || candidate.id)
                            }
                            disabled={votingInProgress}
                            className={`w-full mt-4 py-2 px-4 rounded-lg font-medium transition-colors ${
                              votingInProgress 
                                ? "bg-gray-400 text-gray-600 cursor-not-allowed" 
                                : "bg-blue-600 text-white hover:bg-blue-700"
                            }`}>
                            {votingInProgress ? "Processing..." : `Vote for ${candidate.name}`}
                          </motion.button>
                        )}
                      </div>
                    ))
                  ) : (
                    <p className="text-gray-500 text-center py-4">No candidates added yet</p>
                  )}
                </div>
                
                {user?.isAdmin && (selectedElection.status === "completed" || selectedElection.status === "active") && (
                  <div className="mt-6 p-4 bg-gray-50 rounded-lg">
                    <h4 className="font-semibold text-gray-900 mb-2">
                      {selectedElection.status === "completed" ? "Final Results" : "Current Vote Count"}
                    </h4>
                    <div className="space-y-2">
                      {selectedElection.candidates
                        ?.sort((a, b) => (b.votes || 0) - (a.votes || 0))
                        .map((candidate, index) => (
                          <div key={index} className="flex justify-between items-center">
                            <div className="flex items-center space-x-2">
                              {index === 0 && selectedElection.status === "completed" && (
                                <span className="text-yellow-500">👑</span>
                              )}
                              <span className="font-medium">{candidate.name}</span>
                            </div>
                            <div className="text-right">
                              <span className="font-bold">{candidate.votes || 0} votes</span>
                              {selectedElection.totalVotes > 0 && (
                                <span className="text-sm text-gray-500 ml-2">
                                  ({((candidate.votes || 0) / Math.max(selectedElection.totalVotes, 1) * 100).toFixed(1)}%)
                                </span>
                              )}
                            </div>
                          </div>
                        ))}
                    </div>
                  </div>
                )}
              </div>
            </motion.div>
          </div>
        )}
      </div>
    </div>
  );
}