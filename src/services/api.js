const API_BASE_URL = 'http://localhost:5000/api';

class ApiService {
  constructor() {
    this.baseURL = API_BASE_URL;
  }

  getAuthHeaders() {
    const user = JSON.parse(localStorage.getItem('user') || '{}');
    return {
      'Content-Type': 'application/json',
      ...(user.token && { Authorization: `Bearer ${user.token}` })
    };
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const config = {
      headers: this.getAuthHeaders(),
      ...options
    };

    try {
      const response = await fetch(url, config);
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || `HTTP error! status: ${response.status}`);
      }

      return data;
    } catch (error) {
      console.error(`API request failed: ${endpoint}`, error);
      throw error;
    }
  }

  // Auth endpoints
  async login(credentials) {
    return this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials)
    });
  }

  async adminLogin(credentials) {
    return this.request('/auth/admin-login', {
      method: 'POST',
      body: JSON.stringify(credentials)
    });
  }

  async register(userData) {
    return this.request('/auth/register', {
      method: 'POST',
      body: JSON.stringify(userData)
    });
  }

  async getProfile() {
    return this.request('/auth/profile');
  }

  async updateProfile(profileData) {
    return this.request('/auth/profile', {
      method: 'PUT',
      body: JSON.stringify(profileData)
    });
  }

  // Complaints endpoints
  async getComplaints(params = {}) {
    const queryString = new URLSearchParams(params).toString();
    const endpoint = `/complaints${queryString ? `?${queryString}` : ''}`;
    const response = await this.request(endpoint);
    return response.complaints || response.data || response;
  }

  async getComplaint(id) {
    return this.request(`/complaints/${id}`);
  }

  async createComplaint(complaintData) {
    return this.request('/complaints', {
      method: 'POST',
      body: JSON.stringify(complaintData)
    });
  }

  async updateComplaintStatus(id, status) {
    return this.request(`/complaints/${id}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status })
    });
  }

  async addComplaintResponse(id, responseData) {
    return this.request(`/complaints/${id}/responses`, {
      method: 'POST',
      body: JSON.stringify(responseData)
    });
  }

  async deleteComplaint(id) {
    if (!id || id === 'undefined') {
      throw new Error('Invalid complaint ID');
    }
    return this.request(`/complaints/${id}`, {
      method: 'DELETE'
    });
  }
  async getComplaintStats() {
    return this.request('/complaints/stats/overview');
  }

  // Clubs endpoints
  async getClubs(params = {}) {
    const queryString = new URLSearchParams(params).toString();
    const endpoint = `/clubs${queryString ? `?${queryString}` : ''}`;
    const response = await this.request(endpoint);
    return response.clubs || response.data || response;
  }

  async getClub(id) {
    const response = await this.request(`/clubs/${id}`);
    return response.club || response;
  }

  async createClub(clubData) {
    return this.request('/clubs', {
      method: 'POST',
      body: JSON.stringify(clubData)
    });
  }

  async updateClub(id, clubData) {
    return this.request(`/clubs/${id}`, {
      method: 'PUT',
      body: JSON.stringify(clubData)
    });
  }

  async deleteClub(id) {
    return this.request(`/clubs/${id}`, {
      method: 'DELETE'
    });
  }

  async joinClub(id, joinData) {
    return this.request(`/clubs/${id}/join`, {
      method: 'POST',
      body: JSON.stringify(joinData)
    });
  }

  async leaveClub(id) {
    return this.request(`/clubs/${id}/leave`, {
      method: 'POST'
    });
  }

  async getClubJoinRequests(id) {
    return this.request(`/clubs/${id}/join-requests`);
  }

  async approveClubMember(clubId, memberId) {
    return this.request(`/clubs/${clubId}/members/${memberId}/approve`, {
      method: 'PATCH'
    });
  }

  async rejectClubMember(clubId, memberId) {
    return this.request(`/clubs/${clubId}/members/${memberId}/reject`, {
      method: 'PATCH'
    });
  }

  async removeClubMember(clubId, memberId) {
    return this.request(`/clubs/${clubId}/members/${memberId}`, {
      method: 'DELETE'
    });
  }

  async getClubStats() {
    return this.request('/clubs/stats/overview');
  }

  // Elections endpoints
  async getElections(params = {}) {
    const queryString = new URLSearchParams(params).toString();
    const endpoint = `/elections${queryString ? `?${queryString}` : ''}`;
    const response = await this.request(endpoint);
    return response.elections || response.data || response;
  }

  async getElection(id) {
    return this.request(`/elections/${id}`);
  }

  async createElection(electionData) {
    return this.request('/elections', {
      method: 'POST',
      body: JSON.stringify(electionData)
    });
  }

  async updateElection(id, electionData) {
    return this.request(`/elections/${id}`, {
      method: 'PUT',
      body: JSON.stringify(electionData)
    });
  }

  async deleteElection(id) {
    return this.request(`/elections/${id}`, {
      method: 'DELETE'
    });
  }

  async voteInElection(electionId, candidateId) {
    return this.request(`/elections/${electionId}/vote`, {
      method: 'POST',
      body: JSON.stringify({ candidateId })
    });
  }

  async announceElectionResults(id) {
    return this.request(`/elections/${id}/announce`, {
      method: 'POST'
    });
  }

  async getElectionStats() {
    return this.request('/elections/stats/overview');
  }

  // Posts endpoints
  async getPosts(params = {}) {
    const queryString = new URLSearchParams(params).toString();
    const endpoint = `/posts${queryString ? `?${queryString}` : ''}`;
    const response = await this.request(endpoint);
    return response.posts || response.data || response;
  }

  async getPost(id) {
    return this.request(`/posts/${id}`);
  }

  async createPost(postData) {
    return this.request('/posts', {
      method: 'POST',
      body: JSON.stringify(postData)
    });
  }

  async updatePost(id, postData) {
    return this.request(`/posts/${id}`, {
      method: 'PUT',
      body: JSON.stringify(postData)
    });
  }

  async deletePost(id) {
    return this.request(`/posts/${id}`, {
      method: 'DELETE'
    });
  }

  async likePost(id) {
    return this.request(`/posts/${id}/like`, {
      method: 'POST'
    });
  }

  async addComment(id, commentData) {
    return this.request(`/posts/${id}/comments`, {
      method: 'POST',
      body: JSON.stringify(commentData)
    });
  }

  async registerForEvent(id) {
    return this.request(`/posts/${id}/register`, {
      method: 'POST'
    });
  }

  async getPostStats() {
    return this.request('/posts/stats/overview');
  }

  // Contact endpoints
  async submitContact(contactData) {
    return this.request('/contact', {
      method: 'POST',
      body: JSON.stringify(contactData)
    });
  }

  async getContacts(params = {}) {
    const queryString = new URLSearchParams(params).toString();
    const endpoint = `/contact${queryString ? `?${queryString}` : ''}`;
    return this.request(endpoint);
  }

  async getContact(id) {
    return this.request(`/contact/${id}`);
  }

  async updateContactStatus(id, statusData) {
    return this.request(`/contact/${id}/status`, {
      method: 'PATCH',
      body: JSON.stringify(statusData)
    });
  }

  async replyToContact(id, replyData) {
    return this.request(`/contact/${id}/reply`, {
      method: 'POST',
      body: JSON.stringify(replyData)
    });
  }

  async getContactStats() {
    return this.request('/contact/stats/overview');
  }

  // Users endpoints (Admin only)
  async getUsers(params = {}) {
    const queryString = new URLSearchParams(params).toString();
    const endpoint = `/users${queryString ? `?${queryString}` : ''}`;
    return this.request(endpoint);
  }

  async getUser(id) {
    return this.request(`/users/${id}`);
  }

  async updateUser(id, userData) {
    return this.request(`/users/${id}`, {
      method: 'PUT',
      body: JSON.stringify(userData)
    });
  }

  async deleteUser(id) {
    return this.request(`/users/${id}`, {
      method: 'DELETE'
    });
  }

  async getUserStats() {
    return this.request('/users/stats/overview');
  }

  async resetUserPassword(id, passwordData) {
    return this.request(`/users/${id}/reset-password`, {
      method: 'POST',
      body: JSON.stringify(passwordData)
    });
  }

  async unlockUser(id) {
    return this.request(`/users/${id}/unlock`, {
      method: 'POST'
    });
  }

  // Contact form submission
  async submitContactForm(contactData) {
    return this.request('/contact', {
      method: 'POST',
      body: JSON.stringify(contactData)
    });
  }
}

export const apiService = new ApiService();