import React, { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { useAuth } from "../../contexts/AuthContext";
import { Trash2, Plus, Calendar, MapPin, Clock, Eye, Heart, MessageCircle } from "lucide-react";
import { apiService } from "../../services/api";
import toast from "react-hot-toast";

export function Latest() {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState("News");
  const [posts, setPosts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreateForm, setShowCreateForm] = useState(false);

  const [newPost, setNewPost] = useState({
    title: "",
    content: "",
    type: "News",
    category: "General",
    date: new Date().toISOString().split("T")[0],
    image: "",
    location: "",
    time: "",
    eventDate: "",
    important: false,
  });

  useEffect(() => {
    fetchPosts();
  }, []);

  const fetchPosts = async () => {
    try {
      setLoading(true);
      const response = await apiService.getPosts();
      console.log('Posts API response:', response);
      
      // Handle different response structures
      let postsData = [];
      if (Array.isArray(response)) {
        postsData = response;
      } else if (response.posts && Array.isArray(response.posts)) {
        postsData = response.posts;
      } else if (response.data && Array.isArray(response.data)) {
        postsData = response.data;
      } else if (response.success && response.posts) {
        postsData = response.posts;
      }
      
      setPosts(postsData);
    } catch (error) {
      console.error("Failed to fetch posts:", error);
      toast.error("Failed to load posts");
      setPosts([]);
    } finally {
      setLoading(false);
    }
  };

  const filteredPosts = posts.filter((post) => post.type === activeTab);

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!user?.isAdmin) {
      toast.error("Only admins can create posts");
      return;
    }

    if (!newPost.title.trim() || !newPost.content.trim()) {
      toast.error("Title and content are required");
      return;
    }

    try {
      const postData = {
        title: newPost.title.trim(),
        content: newPost.content.trim(),
        type: newPost.type,
        category: newPost.category,
        date: newPost.date,
        image: newPost.image || null,
      };

      // Add event-specific fields
      if (newPost.type === "Event") {
        postData.location = newPost.location.trim();
        postData.time = newPost.time.trim();
        postData.eventDate = newPost.eventDate || newPost.date;
      }

      // Add announcement-specific fields
      if (newPost.type === "Announcement") {
        postData.important = newPost.important;
      }

      console.log('Creating post with data:', postData);
      
      const response = await apiService.createPost(postData);
      console.log('Create post response:', response);
      
      await fetchPosts(); // Refresh the posts list
      toast.success("Post created successfully!");
      
      // Reset form
      setNewPost({
        title: "",
        content: "",
        type: "News",
        category: "General",
        date: new Date().toISOString().split("T")[0],
        image: "",
        location: "",
        time: "",
        eventDate: "",
        important: false,
      });
      setShowCreateForm(false);
    } catch (error) {
      console.error("Failed to create post:", error);
      toast.error(error.message || "Failed to create post");
    }
  };

  const handleDeletePost = async (postId) => {
    if (!user?.isAdmin) {
      toast.error("Only admins can delete posts");
      return;
    }

    if (!confirm("Are you sure you want to delete this post?")) {
      return;
    }

    try {
      await apiService.deletePost(postId);
      await fetchPosts();
      toast.success("Post deleted successfully!");
    } catch (error) {
      console.error("Failed to delete post:", error);
      toast.error("Failed to delete post");
    }
  };

  const handleLikePost = async (postId) => {
    if (!user) {
      toast.error("Please login to like posts");
      return;
    }

    try {
      await apiService.likePost(postId);
      await fetchPosts(); // Refresh to show updated likes
    } catch (error) {
      console.error("Failed to like post:", error);
      toast.error("Failed to like post");
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-blue-50 to-gray-100">
      {/* Header */}
      <section className="bg-gradient-to-r from-blue-600 to-blue-800 text-white py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
            className="text-center">
            <h1 className="text-4xl md:text-6xl font-bold mb-6">Latest Updates</h1>
            <p className="text-xl md:text-2xl text-blue-100 max-w-4xl mx-auto">
              Stay updated with the latest news, events, and announcements from
              the Student Union of Debre Berhan University
            </p>
          </motion.div>
        </div>
      </section>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="bg-white rounded-2xl shadow-xl overflow-hidden">
          {/* Tabs Navigation */}
          <div className="flex border-b">
            {["News", "Event", "Announcement"].map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-6 py-4 font-medium text-lg flex-1 text-center transition-colors ${
                  activeTab === tab
                    ? "text-blue-600 border-b-2 border-blue-600 bg-blue-50"
                    : "text-gray-600 hover:bg-gray-50"
                }`}>
                {tab === "News" && "📰"} {tab === "Event" && "📅"} {tab === "Announcement" && "📢"} {tab}
              </button>
            ))}
          </div>

          <div className="p-6">
            {/* Admin Create Post Section */}
            {user?.isAdmin && (
              <div className="mb-8 bg-gray-50 rounded-xl p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-semibold text-gray-900">
                    Create New {activeTab}
                  </h3>
                  <button
                    onClick={() => setShowCreateForm(!showCreateForm)}
                    className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center">
                    <Plus className="w-4 h-4 mr-2" />
                    {showCreateForm ? "Cancel" : "Create Post"}
                  </button>
                </div>

                {showCreateForm && (
                  <form onSubmit={handleSubmit} className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-2">
                          Title *
                        </label>
                        <input
                          type="text"
                          value={newPost.title}
                          onChange={(e) =>
                            setNewPost({ ...newPost, title: e.target.value })
                          }
                          className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                          placeholder="Enter post title"
                          required
                        />
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-2">
                          Type
                        </label>
                        <select
                          value={newPost.type}
                          onChange={(e) =>
                            setNewPost({ ...newPost, type: e.target.value })
                          }
                          className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                          <option value="News">News</option>
                          <option value="Event">Event</option>
                          <option value="Announcement">Announcement</option>
                        </select>
                      </div>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">
                        Content *
                      </label>
                      <textarea
                        value={newPost.content}
                        onChange={(e) =>
                          setNewPost({ ...newPost, content: e.target.value })
                        }
                        className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                        rows="4"
                        placeholder="Enter post content"
                        required
                      />
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-2">
                          Category
                        </label>
                        <select
                          value={newPost.category}
                          onChange={(e) =>
                            setNewPost({ ...newPost, category: e.target.value })
                          }
                          className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                          <option value="General">General</option>
                          <option value="Campus">Campus</option>
                          <option value="Academic">Academic</option>
                          <option value="Sports">Sports</option>
                          <option value="Research">Research</option>
                          <option value="Cultural">Cultural</option>
                        </select>
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-2">
                          Date
                        </label>
                        <input
                          type="date"
                          value={newPost.date}
                          onChange={(e) =>
                            setNewPost({ ...newPost, date: e.target.value })
                          }
                          className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                          required
                        />
                      </div>
                    </div>

                    {/* Event-specific fields */}
                    {newPost.type === "Event" && (
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-2">
                            Location
                          </label>
                          <input
                            type="text"
                            value={newPost.location}
                            onChange={(e) =>
                              setNewPost({ ...newPost, location: e.target.value })
                            }
                            className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                            placeholder="Event location"
                          />
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-2">
                            Time
                          </label>
                          <input
                            type="time"
                            value={newPost.time}
                            onChange={(e) =>
                              setNewPost({ ...newPost, time: e.target.value })
                            }
                            className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                          />
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-2">
                            Event Date
                          </label>
                          <input
                            type="date"
                            value={newPost.eventDate}
                            onChange={(e) =>
                              setNewPost({ ...newPost, eventDate: e.target.value })
                            }
                            className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                          />
                        </div>
                      </div>
                    )}

                    {/* Announcement-specific fields */}
                    {newPost.type === "Announcement" && (
                      <div className="flex items-center">
                        <input
                          type="checkbox"
                          id="important"
                          checked={newPost.important}
                          onChange={(e) =>
                            setNewPost({ ...newPost, important: e.target.checked })
                          }
                          className="h-4 w-4 text-blue-600 rounded focus:ring-blue-500"
                        />
                        <label htmlFor="important" className="ml-2 text-sm text-gray-700">
                          Mark as Important
                        </label>
                      </div>
                    )}

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">
                        Image URL (optional)
                      </label>
                      <input
                        type="url"
                        value={newPost.image}
                        onChange={(e) =>
                          setNewPost({ ...newPost, image: e.target.value })
                        }
                        className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                        placeholder="https://example.com/image.jpg"
                      />
                    </div>

                    <div className="flex gap-4">
                      <button
                        type="submit"
                        className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors">
                        Create {newPost.type}
                      </button>
                      <button
                        type="button"
                        onClick={() => setShowCreateForm(false)}
                        className="bg-gray-600 text-white px-6 py-2 rounded-lg hover:bg-gray-700 transition-colors">
                        Cancel
                      </button>
                    </div>
                  </form>
                )}
              </div>
            )}

            {/* Posts List */}
            {loading ? (
              <div className="text-center py-8">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
                <p className="mt-4 text-gray-600">Loading posts...</p>
              </div>
            ) : (
              <div className="space-y-6">
                {filteredPosts.length > 0 ? (
                  filteredPosts.map((post, index) => (
                    <PostCard
                      key={post._id || post.id || index}
                      post={post}
                      onDelete={handleDeletePost}
                      onLike={handleLikePost}
                      canDelete={user?.isAdmin}
                      user={user}
                    />
                  ))
                ) : (
                  <div className="bg-blue-50 rounded-xl p-8 text-center">
                    <div className="text-4xl text-blue-500 mb-4">📥</div>
                    <h3 className="text-xl font-semibold text-gray-700">
                      No {activeTab.toLowerCase()} posts yet
                    </h3>
                    <p className="text-gray-600 mt-2">
                      {activeTab === "News" && "Be the first to share campus news!"}
                      {activeTab === "Event" && "No upcoming events scheduled yet."}
                      {activeTab === "Announcement" && "No announcements at this time."}
                    </p>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// Post Card Component
function PostCard({ post, onDelete, onLike, canDelete, user }) {
  const formatDate = (dateString) => {
    try {
      return new Date(dateString).toLocaleDateString();
    } catch {
      return "Invalid Date";
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className={`bg-white rounded-xl shadow-md overflow-hidden border transition-all hover:shadow-lg ${
        post.important ? "border-l-4 border-red-500" : "border-gray-200"
      }`}>
      
      {post.image && (
        <div className="w-full h-48 overflow-hidden">
          <img
            src={post.image}
            alt={post.title}
            className="w-full h-full object-cover"
            onError={(e) => {
              e.target.style.display = 'none';
            }}
          />
        </div>
      )}

      <div className="p-6">
        <div className="flex justify-between items-start mb-4">
          <div className="flex items-center space-x-2">
            <span
              className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${
                post.type === "News"
                  ? "bg-blue-100 text-blue-800"
                  : post.type === "Event"
                  ? "bg-green-100 text-green-800"
                  : "bg-yellow-100 text-yellow-800"
              }`}>
              {post.type === "News" && "📰"}
              {post.type === "Event" && "📅"}
              {post.type === "Announcement" && "📢"}
              <span className="ml-1">{post.type}</span>
            </span>
            
            {post.category && (
              <span className="inline-flex items-center px-2 py-1 bg-gray-100 text-gray-700 rounded-full text-xs">
                {post.category}
              </span>
            )}

            {post.important && (
              <span className="inline-flex items-center px-2 py-1 bg-red-100 text-red-800 rounded-full text-xs">
                ⚠️ Important
              </span>
            )}
          </div>

          <div className="flex items-center space-x-2">
            <span className="text-gray-500 text-sm">
              {formatDate(post.date || post.createdAt)}
            </span>
            {canDelete && (
              <button
                onClick={() => onDelete(post._id || post.id)}
                className="text-red-600 hover:text-red-700 p-1 rounded">
                <Trash2 className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>

        <h3 className="text-xl font-bold text-gray-900 mb-3">{post.title}</h3>
        <p className="text-gray-600 mb-4 leading-relaxed">{post.content}</p>

        {/* Event Details */}
        {post.type === "Event" && (post.location || post.time || post.eventDate) && (
          <div className="bg-blue-50 rounded-lg p-4 mb-4">
            <h4 className="font-medium text-blue-900 mb-2">Event Details</h4>
            <div className="space-y-2">
              {post.location && (
                <div className="flex items-center text-sm text-blue-800">
                  <MapPin className="w-4 h-4 mr-2" />
                  <span>{post.location}</span>
                </div>
              )}
              {post.time && (
                <div className="flex items-center text-sm text-blue-800">
                  <Clock className="w-4 h-4 mr-2" />
                  <span>{post.time}</span>
                </div>
              )}
              {post.eventDate && (
                <div className="flex items-center text-sm text-blue-800">
                  <Calendar className="w-4 h-4 mr-2" />
                  <span>{formatDate(post.eventDate)}</span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Post Stats */}
        <div className="flex items-center justify-between pt-4 border-t border-gray-100">
          <div className="flex items-center space-x-4">
            <button
              onClick={() => onLike && onLike(post._id || post.id)}
              className="flex items-center space-x-1 text-gray-500 hover:text-red-500 transition-colors">
              <Heart className="w-4 h-4" />
              <span className="text-sm">{post.likeCount || post.likes?.length || 0}</span>
            </button>
            
            <div className="flex items-center space-x-1 text-gray-500">
              <MessageCircle className="w-4 h-4" />
              <span className="text-sm">{post.commentCount || post.comments?.length || 0}</span>
            </div>
            
            <div className="flex items-center space-x-1 text-gray-500">
              <Eye className="w-4 h-4" />
              <span className="text-sm">{post.views || 0}</span>
            </div>
          </div>

          {post.author && (
            <div className="text-sm text-gray-500">
              By {post.author.name || post.author}
            </div>
          )}
        </div>
      </div>
    </motion.div>
  );
}