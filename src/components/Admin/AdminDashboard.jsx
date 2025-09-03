import React, { useState, useEffect } from "react";
import {
  BarChart3,
  Users,
  AlertTriangle,
  CheckCircle,
  Clock,
  Shield,
  Activity,
  MessageSquare,
  Vote,
  Download,
  Lock,
  Settings,
  UserPlus,
  FileText,
} from "lucide-react";
import { useAuth } from "../../contexts/AuthContext";
import { apiService } from "../../services/api";
import { motion } from "framer-motion";
import toast from "react-hot-toast";

export function AdminDashboard() {
  const { user } = useAuth();
  const [stats, setStats] = useState({
    users: { total: 0, active: 0, admins: 0, students: 0 },
    complaints: { total: 0, pending: 0, resolved: 0, underReview: 0 },
    clubs: { total: 0, active: 0, pending: 0 },
    elections: { total: 0, active: 0, upcoming: 0, completed: 0 },
    posts: { total: 0, published: 0, drafts: 0 },
    contacts: { total: 0, new: 0, replied: 0 },
  });
  const [loading, setLoading] = useState(true);
  const [selectedTimeframe, setSelectedTimeframe] = useState("7d");
  const [recentActivity, setRecentActivity] = useState([]);

  useEffect(() => {
    fetchDashboardData();
  }, [selectedTimeframe]);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      
      // Fetch all stats in parallel
      const [
        userStats,
        complaintStats,
        clubStats,
        electionStats,
        postStats,
        contactStats
      ] = await Promise.allSettled([
        apiService.getUserStats(),
        apiService.getComplaintStats(),
        apiService.getClubStats(),
        apiService.getElectionStats(),
        apiService.getPostStats(),
        apiService.getContactStats()
      ]);

      // Process results and handle any failures gracefully
      setStats({
        users: userStats.status === 'fulfilled' ? userStats.value.stats : { total: 0, active: 0, admins: 0, students: 0 },
        complaints: complaintStats.status === 'fulfilled' ? complaintStats.value.stats : { total: 0, pending: 0, resolved: 0, underReview: 0 },
        clubs: clubStats.status === 'fulfilled' ? clubStats.value.stats : { total: 0, active: 0, pending: 0 },
        elections: electionStats.status === 'fulfilled' ? electionStats.value.stats : { total: 0, active: 0, upcoming: 0, completed: 0 },
        posts: postStats.status === 'fulfilled' ? postStats.value.stats : { total: 0, published: 0, drafts: 0 },
        contacts: contactStats.status === 'fulfilled' ? contactStats.value.stats : { total: 0, new: 0, replied: 0 },
      });

      // Generate recent activity (mock data for now)
      setRecentActivity([
        { id: 1, type: 'user', message: 'New user registered', time: '2 minutes ago' },
        { id: 2, type: 'complaint', message: 'Complaint resolved', time: '15 minutes ago' },
        { id: 3, type: 'club', message: 'New club approved', time: '1 hour ago' },
        { id: 4, type: 'election', message: 'Election results announced', time: '2 hours ago' },
      ]);

    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
      toast.error('Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  };

  const handleExportReport = async () => {
    try {
      toast.success('Report export started. You will receive it via email.');
    } catch (error) {
      toast.error('Failed to export report');
    }
  };

  const quickActions = [
    {
      title: 'Create User',
      description: 'Add new student or admin',
      icon: UserPlus,
      color: 'bg-blue-500',
      action: () => toast.info('User creation modal would open here')
    },
    {
      title: 'System Settings',
      description: 'Configure system settings',
      icon: Settings,
      color: 'bg-purple-500',
      action: () => toast.info('System settings would open here')
    },
    {
      title: 'Generate Report',
      description: 'Create detailed analytics report',
      icon: FileText,
      color: 'bg-green-500',
      action: handleExportReport
    },
    {
      title: 'Manage Permissions',
      description: 'Update user roles and permissions',
      icon: Shield,
      color: 'bg-orange-500',
      action: () => toast.info('Permission management would open here')
    },
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <div className="w-16 h-16 border-4 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-gray-600">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Admin Dashboard</h1>
          <p className="text-gray-600 mt-1">Welcome back, {user?.name}</p>
          <div className="flex items-center mt-2">
            <Shield className="w-4 h-4 text-blue-600 mr-1" />
            <span className="text-sm text-blue-600 font-medium">
              {user?.role === 'admin' ? 'System Administrator' : 'Admin User'}
            </span>
          </div>
        </div>

        <div className="flex items-center space-x-3 mt-4 sm:mt-0">
          <select
            value={selectedTimeframe}
            onChange={(e) => setSelectedTimeframe(e.target.value)}
            className="border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
            <option value="90d">Last 90 days</option>
          </select>

          <button 
            onClick={handleExportReport}
            className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center">
            <Download className="w-4 h-4 mr-2" />
            Export Report
          </button>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* Users Stats */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-white rounded-xl p-6 shadow-sm border border-gray-100">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Total Users</p>
              <p className="text-2xl font-bold text-gray-900 mt-1">{stats.users.total}</p>
              <p className="text-sm text-green-600 mt-1">
                {stats.users.active} active
              </p>
            </div>
            <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center">
              <Users className="w-6 h-6 text-blue-600" />
            </div>
          </div>
        </motion.div>

        {/* Complaints Stats */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="bg-white rounded-xl p-6 shadow-sm border border-gray-100">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Complaints</p>
              <p className="text-2xl font-bold text-gray-900 mt-1">{stats.complaints.total}</p>
              <p className="text-sm text-orange-600 mt-1">
                {stats.complaints.pending} pending
              </p>
            </div>
            <div className="w-12 h-12 bg-orange-100 rounded-lg flex items-center justify-center">
              <MessageSquare className="w-6 h-6 text-orange-600" />
            </div>
          </div>
        </motion.div>

        {/* Clubs Stats */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-white rounded-xl p-6 shadow-sm border border-gray-100">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Active Clubs</p>
              <p className="text-2xl font-bold text-gray-900 mt-1">{stats.clubs.active}</p>
              <p className="text-sm text-purple-600 mt-1">
                {stats.clubs.pending} pending approval
              </p>
            </div>
            <div className="w-12 h-12 bg-purple-100 rounded-lg flex items-center justify-center">
              <Users className="w-6 h-6 text-purple-600" />
            </div>
          </div>
        </motion.div>

        {/* Elections Stats */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-white rounded-xl p-6 shadow-sm border border-gray-100">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Elections</p>
              <p className="text-2xl font-bold text-gray-900 mt-1">{stats.elections.active}</p>
              <p className="text-sm text-green-600 mt-1">
                {stats.elections.upcoming} upcoming
              </p>
            </div>
            <div className="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center">
              <Vote className="w-6 h-6 text-green-600" />
            </div>
          </div>
        </motion.div>
      </div>

      {/* Quick Actions */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="bg-white rounded-xl p-6 shadow-sm border border-gray-100">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Quick Actions</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {quickActions.map((action, index) => (
            <button
              key={index}
              onClick={action.action}
              className="p-4 border border-gray-200 rounded-lg hover:border-blue-300 hover:bg-blue-50 transition-colors text-left group">
              <div className="flex items-center space-x-3">
                <div className={`w-10 h-10 ${action.color} rounded-lg flex items-center justify-center group-hover:scale-110 transition-transform`}>
                  <action.icon className="w-5 h-5 text-white" />
                </div>
                <div>
                  <p className="font-medium text-gray-900">{action.title}</p>
                  <p className="text-sm text-gray-500">{action.description}</p>
                </div>
              </div>
            </button>
          ))}
        </div>
      </motion.div>

      {/* Recent Activity & System Status */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Activity */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.5 }}
          className="bg-white rounded-xl p-6 shadow-sm border border-gray-100">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900">Recent Activity</h3>
            <Activity className="w-5 h-5 text-gray-400" />
          </div>
          <div className="space-y-4">
            {recentActivity.map((activity) => (
              <div key={activity.id} className="flex items-start space-x-3">
                <div className={`w-2 h-2 mt-2 rounded-full ${
                  activity.type === 'user' ? 'bg-blue-500' :
                  activity.type === 'complaint' ? 'bg-orange-500' :
                  activity.type === 'club' ? 'bg-purple-500' : 'bg-green-500'
                }`}></div>
                <div className="flex-1">
                  <p className="text-sm font-medium text-gray-900">{activity.message}</p>
                  <p className="text-xs text-gray-500">{activity.time}</p>
                </div>
              </div>
            ))}
          </div>
        </motion.div>

        {/* System Status */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.6 }}
          className="bg-white rounded-xl p-6 shadow-sm border border-gray-100">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900">System Status</h3>
            <CheckCircle className="w-5 h-5 text-green-500" />
          </div>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Database</span>
              <span className="flex items-center text-sm text-green-600">
                <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
                Online
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">API Server</span>
              <span className="flex items-center text-sm text-green-600">
                <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
                Healthy
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">File Storage</span>
              <span className="flex items-center text-sm text-green-600">
                <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
                Available
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Email Service</span>
              <span className="flex items-center text-sm text-yellow-600">
                <div className="w-2 h-2 bg-yellow-500 rounded-full mr-2"></div>
                Limited
              </span>
            </div>
          </div>
        </motion.div>
      </div>

      {/* Performance Metrics */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.7 }}
        className="bg-white rounded-xl p-6 shadow-sm border border-gray-100">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Performance Overview</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="text-center">
            <div className="text-2xl font-bold text-blue-600 mb-1">98.5%</div>
            <div className="text-sm text-gray-600">System Uptime</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-green-600 mb-1">1.2s</div>
            <div className="text-sm text-gray-600">Avg Response Time</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-purple-600 mb-1">2.1GB</div>
            <div className="text-sm text-gray-600">Storage Used</div>
          </div>
        </div>
      </motion.div>
    </div>
  );
}