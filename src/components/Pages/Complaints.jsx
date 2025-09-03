/** @format */

import React, { useState } from "react";
import { useEffect } from "react";
import {
	MessageSquare,
	Plus,
	Clock,
	CheckCircle,
	AlertCircle,
	Send,
	Filter,
	Search,
	Upload,
} from "lucide-react";
import { useAuth } from "../../contexts/AuthContext";
import { generateCaseId } from "../../data/mockData";
import { apiService } from "../../services/api";
import { motion } from "framer-motion";
import toast from "react-hot-toast";

export function Complaints() {
	const { user } = useAuth();

	const [selectedTab, setSelectedTab] = useState("all");
	const [showNewComplaint, setShowNewComplaint] = useState(false);
	const [selectedComplaint, setSelectedComplaint] = useState(null);
	const [searchTerm, setSearchTerm] = useState("");
	const [statusFilter, setStatusFilter] = useState("all");
	const [responseMessage, setResponseMessage] = useState("");
	const [complaints, setComplaints] = useState([]);
	const [loading, setLoading] = useState(true);
	const [showDocumentUpload, setShowDocumentUpload] = useState(false);
	const [documentFile, setDocumentFile] = useState(null);

	const [newComplaintForm, setNewComplaintForm] = useState({
		title: "",
		description: "",
		category: "",
		priority: "medium",
		evidence: [],
	});

	const complaintCategories = [
		{ value: "academic", label: "Academic Affairs" },
		{ value: "dining", label: "Dining Services" },
		{ value: "housing", label: "Housing" },
		{ value: "facilities", label: "Facilities" },
		{ value: "disciplinary", label: "Disciplinary" },
		{ value: "general", label: "General" },
	];

	useEffect(() => {
		fetchComplaints();
	}, []);

	const fetchComplaints = async () => {
		try {
			setLoading(true);
			const data = await apiService.getComplaints();
			setComplaints(Array.isArray(data) ? data : []);
		} catch (error) {
			console.error("Failed to fetch complaints:", error);
			toast.error("Failed to load complaints");
			setComplaints([]);
		} finally {
			setLoading(false);
		}
	};

	const filteredComplaints = complaints.filter((complaint) => {
		const matchesSearch =
			complaint.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
			complaint.description.toLowerCase().includes(searchTerm.toLowerCase());
		const matchesStatus =
			statusFilter === "all" || complaint.status === statusFilter;
		const matchesTab =
			selectedTab === "all" ||
			(selectedTab === "my" && complaint.submittedBy === user?.id) ||
			(selectedTab === "pending" && complaint.status === "submitted");
		return matchesSearch && matchesStatus && matchesTab;
	});

	const handleSubmitComplaint = async (e) => {
		e.preventDefault();
		if (!newComplaintForm.title || !newComplaintForm.description) {
			toast.error("Please fill all required fields");
			return;
		}

		try {
			const complaintData = {
				...newComplaintForm,
				branch: newComplaintForm.category,
			};

			await apiService.createComplaint(complaintData);
			await fetchComplaints(); // Refresh the complaints list
			toast.success("Complaint submitted successfully!");
			setShowNewComplaint(false);
			setNewComplaintForm({
				title: "",
				description: "",
				category: "",
				priority: "medium",
				evidence: [],
			});
		} catch (error) {
			console.error('Failed to submit complaint:', error);
			toast.error(`Failed to submit complaint: ${error.message}`);
		}
	};

	const handleSendResponse = (complaintId) => {
		if (!responseMessage.trim()) return;

		const sendResponse = async () => {
			try {
				await apiService.addComplaintResponse(complaintId, { message: responseMessage });
				await fetchComplaints(); // Refresh complaints
				toast.success("Response sent and complaint resolved");
				setResponseMessage("");
			} catch (error) {
				console.error('Failed to send response:', error);
				toast.error(`Failed to send response: ${error.message}`);
			}
		};

		sendResponse();
	};

	const handleDocumentUpload = (e) => {
		e.preventDefault();
		if (!documentFile) {
			toast.error("Please select a document to upload");
			return;
		}

		if (
			!user?.isAdmin ||
			(user?.role !== "president" && user?.role !== "student_din")
		) {
			toast.error("Only branch admins can upload documents");
			return;
		}

		// Simulate document upload
		toast.success("Document uploaded successfully to Student Din/President");
		setDocumentFile(null);
		setShowDocumentUpload(false);
	};

	const handleResolveComplaint = async (complaintId) => {
		if (!user?.isAdmin) {
			toast.error("Only admins can resolve complaints");
			return;
		}

		try {
			await apiService.updateComplaintStatus(complaintId, "resolved");
			await fetchComplaints(); // Refresh complaints
			toast.success("Complaint resolved successfully");
		} catch (error) {
			console.error('Failed to resolve complaint:', error);
			toast.error(`Failed to resolve complaint: ${error.message}`);
		}
	};

	const handleDeleteComplaint = async (complaintId) => {
		if (!user?.isAdmin) {
			toast.error("Only admins can delete complaints");
			return;
		}

		if (!confirm("Are you sure you want to delete this complaint?")) {
			return;
		}

		try {
			await apiService.deleteComplaint(complaintId);
			await fetchComplaints();
			toast.success("Complaint deleted successfully");
		} catch (error) {
			console.error('Failed to delete complaint:', error);
			toast.error(`Failed to delete complaint: ${error.message}`);
		}
	};
	const getStatusIcon = (status) => {
		switch (status) {
			case "submitted":
				return <Clock className="w-5 h-5 text-yellow-500" />;
			case "under_review":
				return <AlertCircle className="w-5 h-5 text-blue-500" />;
			case "resolved":
				return <CheckCircle className="w-5 h-5 text-green-500" />;
			case "closed":
				return <CheckCircle className="w-5 h-5 text-gray-500" />;
			default:
				return <Clock className="w-5 h-5 text-gray-500" />;
		}
	};

	const getStatusColor = (status) => {
		switch (status) {
			case "submitted":
				return "bg-yellow-100 text-yellow-800";
			case "under_review":
				return "bg-blue-100 text-blue-800";
			case "resolved":
				return "bg-green-100 text-green-800";
			case "closed":
				return "bg-gray-100 text-gray-800";
			default:
				return "bg-gray-100 text-gray-800";
		}
	};

	const getPriorityColor = (priority) => {
		switch (priority) {
			case "high":
				return "bg-red-100 text-red-800";
			case "medium":
				return "bg-yellow-100 text-yellow-800";
			case "low":
				return "bg-green-100 text-green-800";
			default:
				return "bg-gray-100 text-gray-800";
		}
	};

	// Component for individual complaint card
	const ComplaintCard = ({ 
		complaint, 
		user, 
		selectedComplaint, 
		setSelectedComplaint, 
		responseMessage, 
		setResponseMessage, 
		handleSendResponse, 
		handleResolveComplaint,
		handleDeleteComplaint,
		getStatusIcon,
		getStatusColor,
		getPriorityColor
	}) => (
		<div className="bg-white rounded-xl p-6 shadow-sm border border-gray-100">
			<div className="flex justify-between">
				<div>
					<h3 className="text-lg font-semibold text-gray-900">
						{complaint.title}
					</h3>
					<p className="text-gray-600">{complaint.description}</p>
					<div className="flex gap-2 mt-2 text-sm">
						<span
							className={`px-2 py-1 rounded-full flex items-center ${getStatusColor(
								complaint.status
							)}`}>
							{getStatusIcon(complaint.status)}{" "}
							<span className="ml-1">
								{complaint.status.replace("_", " ")}
							</span>
						</span>
						<span
							className={`px-2 py-1 rounded-full ${getPriorityColor(
								complaint.priority
							)}`}>
							{complaint.priority} priority
						</span>
						<span className="text-gray-500">
							{new Date(complaint.submittedAt || complaint.createdAt).toLocaleDateString()}
						</span>
					</div>
				</div>
				<div className="flex items-center space-x-2">
					{user?.isAdmin && complaint.status !== "resolved" && (
						<button
							onClick={() => handleResolveComplaint(complaint._id || complaint.id)}
							className="bg-green-600 text-white px-3 py-1 rounded text-sm hover:bg-green-700 transition-colors">
							Resolve
						</button>
					)}
					{user?.isAdmin && (
						<button
							onClick={() => handleDeleteComplaint(complaint._id || complaint.id)}
							className="bg-red-600 text-white px-3 py-1 rounded text-sm hover:bg-red-700 transition-colors">
							Delete
						</button>
					)}
					<button
						className="text-blue-600 hover:underline"
						onClick={() =>
							setSelectedComplaint(
								selectedComplaint === (complaint._id || complaint.id)
									? null
									: (complaint._id || complaint.id)
							)
						}>
						{selectedComplaint === (complaint._id || complaint.id) ? "Hide" : "Details"}
					</button>
				</div>
			</div>

			{selectedComplaint === (complaint._id || complaint.id) && (
				<div className="mt-4 border-t pt-4">
					<h4 className="font-semibold text-gray-800 mb-2">
						Responses:
					</h4>
					{complaint.responses && complaint.responses.length > 0 ? (
						complaint.responses.map((r, index) => (
							<div key={r._id || r.id || index} className="bg-gray-50 rounded p-3 mb-2">
								<div className="flex justify-between text-sm">
									<span className="font-medium">{r.author}</span>
									<span className="text-gray-500">
										{new Date(r.timestamp).toLocaleDateString()}
									</span>
								</div>
								<p className="text-gray-700 mt-1">{r.message}</p>
							</div>
						))
					) : (
						<p className="text-gray-500 text-sm">No responses yet.</p>
					)}

					{user?.isAdmin && (
						<div className="flex gap-2 mt-4">
							<input
								type="text"
								value={responseMessage}
								onChange={(e) => setResponseMessage(e.target.value)}
								className="flex-1 border border-gray-300 rounded px-3 py-2"
								placeholder="Write a response..."
							/>
							<button
								onClick={() => handleSendResponse(complaint._id || complaint.id)}
								className="bg-blue-600 text-white px-4 py-2 rounded">
								<Send className="w-4 h-4" />
							</button>
						</div>
					)}
				</div>
			)}
		</div>
	);

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
							Complaints & Appeals
						</h1>
						<p className="text-xl md:text-2xl text-blue-100 max-w-4xl mx-auto">
							Submit complaints and track their status
						</p>
					</motion.div>
				</div>
			</div>

			<div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
				<div className="flex justify-between items-center">
					<div>
						<h2 className="text-2xl font-bold text-gray-900">
							Complaints & Appeals
						</h2>
						<p className="text-gray-600 mt-1">
							Submit complaints and track their status
						</p>
					</div>
					<div className="flex space-x-4">
						{user?.isAdmin && (
							<motion.button
								whileHover={{ scale: 1.02 }}
								whileTap={{ scale: 0.98 }}
								onClick={() => setShowDocumentUpload(true)}
								className="px-4 py-2 bg-green-600 text-white rounded-lg font-medium hover:bg-green-700 transition-colors">
								<Upload className="w-4 h-4 inline mr-2" />
								Upload Document
							</motion.button>
						)}
						<motion.button
							whileHover={{ scale: 1.02 }}
							whileTap={{ scale: 0.98 }}
							onClick={() => setShowNewComplaint(true)}
							className="px-4 py-2 bg-blue-600 text-white rounded-lg font-medium hover:bg-blue-700 transition-colors">
							<Plus className="w-4 h-4 inline mr-2" />
							New Complaint
						</motion.button>
					</div>
				</div>

				{/* Filters */}
				<div className="bg-white rounded-xl p-6 shadow-sm border border-gray-100 space-y-4">
					<div className="flex flex-col lg:flex-row gap-4">
						<div className="relative flex-1">
							<Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
							<input
								type="text"
								placeholder="Search complaints..."
								value={searchTerm}
								onChange={(e) => setSearchTerm(e.target.value)}
								className="pl-10 w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
							/>
						</div>
						<div className="flex gap-4 items-center">
							<Filter className="w-5 h-5 text-gray-400" />
							<select
								value={statusFilter}
								onChange={(e) => setStatusFilter(e.target.value)}
								className="border border-gray-300 rounded-lg px-3 py-2">
								<option value="all">All Status</option>
								<option value="submitted">Submitted</option>
								<option value="under_review">Under Review</option>
								<option value="resolved">Resolved</option>
								<option value="closed">Closed</option>
							</select>
						</div>
					</div>

					<div className="flex gap-2">
						{["all", "my", "pending"].map((tab) => (
							<button
								key={tab}
								onClick={() => setSelectedTab(tab)}
								className={`px-3 py-1 rounded-md text-sm font-medium transition-colors ${
									selectedTab === tab
										? "bg-blue-600 text-white"
										: "text-gray-500 hover:bg-gray-100"
								}`}>
								{tab === "all"
									? "All"
									: tab === "my"
									? "My Complaints"
									: "Pending"}
							</button>
						))}
					</div>
				</div>

				{/* Complaint List */}
				{loading ? (
					<div className="text-center py-8">
						<div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
						<p className="mt-4 text-gray-600">Loading complaints...</p>
					</div>
				) : (
					<div className="space-y-4">
						{filteredComplaints.map((complaint) => (
							<ComplaintCard
								key={complaint._id || complaint.id}
								complaint={complaint}
								user={user}
								selectedComplaint={selectedComplaint}
								setSelectedComplaint={setSelectedComplaint}
								responseMessage={responseMessage}
								setResponseMessage={setResponseMessage}
								handleSendResponse={handleSendResponse}
								handleResolveComplaint={handleResolveComplaint}
								handleDeleteComplaint={handleDeleteComplaint}
								getStatusIcon={getStatusIcon}
								getStatusColor={getStatusColor}
								getPriorityColor={getPriorityColor}
							/>
						))}
					</div>
				)}

				{/* New Complaint Modal */}
				{showNewComplaint && (
					<div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
						<motion.div
							initial={{ opacity: 0, scale: 0.95 }}
							animate={{ opacity: 1, scale: 1 }}
							className="bg-white rounded-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
							<div className="p-6">
								<div className="flex items-center justify-between mb-6">
									<h2 className="text-xl font-bold text-gray-900">
										Submit New Complaint
									</h2>
									<button
										onClick={() => setShowNewComplaint(false)}
										className="text-gray-400 hover:text-gray-600">
										✕
									</button>
								</div>

								<form onSubmit={handleSubmitComplaint} className="space-y-4">
									<div>
										<label className="block text-sm font-medium text-gray-700 mb-2">
											Title *
										</label>
										<input
											type="text"
											required
											value={newComplaintForm.title}
											onChange={(e) =>
												setNewComplaintForm({
													...newComplaintForm,
													title: e.target.value,
												})
											}
											className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
											placeholder="Brief title of your complaint"
										/>
									</div>

									<div>
										<label className="block text-sm font-medium text-gray-700 mb-2">
											Category
										</label>
										<select
											value={newComplaintForm.category}
											onChange={(e) =>
												setNewComplaintForm({
													...newComplaintForm,
													category: e.target.value,
												})
											}
											className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
											<option value="">Select category</option>
											{complaintCategories.map((cat) => (
												<option key={cat.value} value={cat.value}>
													{cat.label}
												</option>
											))}
										</select>
									</div>

									<div>
										<label className="block text-sm font-medium text-gray-700 mb-2">
											Priority
										</label>
										<select
											value={newComplaintForm.priority}
											onChange={(e) =>
												setNewComplaintForm({
													...newComplaintForm,
													priority: e.target.value,
												})
											}
											className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
											<option value="low">Low</option>
											<option value="medium">Medium</option>
											<option value="high">High</option>
										</select>
									</div>

									<div>
										<label className="block text-sm font-medium text-gray-700 mb-2">
											Description *
										</label>
										<textarea
											required
											rows={4}
											value={newComplaintForm.description}
											onChange={(e) =>
												setNewComplaintForm({
													...newComplaintForm,
													description: e.target.value,
												})
											}
											className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
											placeholder="Detailed description of your complaint"
										/>
									</div>

									<div className="flex justify-end space-x-3">
										<button
											type="button"
											onClick={() => setShowNewComplaint(false)}
											className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50">
											Cancel
										</button>
										<button
											type="submit"
											className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
											Submit Complaint
										</button>
									</div>
								</form>
							</div>
						</motion.div>
					</div>
				)}

				{/* Document Upload Modal */}
				{showDocumentUpload && (
					<div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
						<motion.div
							initial={{ opacity: 0, scale: 0.95 }}
							animate={{ opacity: 1, scale: 1 }}
							className="bg-white rounded-2xl max-w-md w-full">
							<div className="p-6">
								<div className="flex items-center justify-between mb-6">
									<h2 className="text-xl font-bold text-gray-900">
										Upload Document
									</h2>
									<button
										onClick={() => setShowDocumentUpload(false)}
										className="text-gray-400 hover:text-gray-600">
										✕
									</button>
								</div>

								<form onSubmit={handleDocumentUpload} className="space-y-4">
									<div>
										<label className="block text-sm font-medium text-gray-700 mb-2">
											Select Document
										</label>
										<input
											type="file"
											onChange={(e) => setDocumentFile(e.target.files[0])}
											className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
											accept=".pdf,.doc,.docx,.txt"
										/>
									</div>

									<p className="text-sm text-gray-600">
										This document will be sent to Student Din and President for
										review.
									</p>

									<div className="flex justify-end space-x-3">
										<button
											type="button"
											onClick={() => setShowDocumentUpload(false)}
											className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50">
											Cancel
										</button>
										<button
											type="submit"
											className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700">
											Upload Document
										</button>
									</div>
								</form>
							</div>
						</motion.div>
					</div>
				)}
			</div>
		</div>
	);
}
