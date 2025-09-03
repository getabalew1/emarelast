/** @format */

import React from "react";
import { Link } from "react-router-dom";
import { Vote, Users, MessageSquare, Building, ArrowRight } from "lucide-react";
import { useAuth } from "../../contexts/AuthContext";
import { motion } from "framer-motion";
import "../../app.css";
export const Home = () => {
	const { user } = useAuth();

	const features = [
		{
			icon: Vote,
			title: "Democratic Elections",
			description: "Participate in secure, transparent student elections",
			link: "/elections",
		},
		{
			icon: Users,
			title: "Student Clubs",
			description: "Join or create clubs and associations",
			link: "/clubs",
		},
		{
			icon: MessageSquare,
			title: "Voice Your Concerns",
			description: "Submit complaints and track their resolution",
			link: "/complaints",
		},
		{
			icon: Building,
			title: "Branch Services",
			description: "Access specialized services from different branches",
			link: "/services",
		},
	];

	const stats = [
		{ number: "12,547", label: "Active Students" },
		{ number: "47", label: "Student Clubs" },
		{ number: "10", label: "Service Branches" },
		{ number: "95%", label: "Satisfaction Rate" },
	];

	const announcements = [
		{
			id: 1,
			title: "Student Union President Election 2024",
			date: "2024-02-01",
			urgent: true,
		},
		{
			id: 2,
			title: "Annual Cultural Festival Registration Open",
			date: "2024-01-25",
			urgent: false,
		},
		{
			id: 3,
			title: "New Club Registration Guidelines Updated",
			date: "2024-01-20",
			urgent: false,
		},
	];

	return (
		<div className="min-h-screen bg-gray-50">
			{/* Hero Section */}
			<section className="bg-img text-white">
				<div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
					<div className="text-center">
						<motion.div
							initial={{ opacity: 0, y: 30 }}
							animate={{ opacity: 1, y: 0 }}
							transition={{ duration: 0.8 }}>
							<div className="flex items-center justify-center mb-8">
								<div className="w-20 h-20 bg-img-lg bg-opacity-20 rounded-2xl flex items-center justify-center mr-4">
									<span className="text-3xl font-bold"></span>
								</div>
								<div className="text-left">
									<h1 className="text-4xl md:text-6xl font-bold mb-2 text-white">
										Student Union
									</h1>
									<p className="text-xl text-white">Debre Berhan University</p>
								</div>
							</div>

							<p className="text-xl md:text-2xl  mb-8 max-w-3xl mx-auto">
								Your Voice, Your Choice, Your Future
							</p>

							<div className="flex flex-col sm:flex-row gap-4 justify-center">
								{!user ? (
									<>
										<Link
											to="/login"
											className="bg-white text-blue-700 px-8 py-4 rounded-xl font-semibold hover:bg-blue-50 transition-colors">
											Get Started
										</Link>
										<Link
											to="/about"
											className="border-2 border-white text-white px-8 py-4 rounded-xl font-semibold hover:bg-white hover:text-blue-700 transition-colors">
											Learn More
										</Link>
									</>
								) : (
									<div className="text-center">
										<p className="text-blue-100 mb-4">Welcome back! You're logged in as {user.isAdmin ? 'Admin' : 'Student'}</p>
										<Link
											to="/dashboard"
											className="bg-white text-blue-700 px-8 py-4 rounded-xl font-semibold hover:bg-blue-50 transition-colors">
											Go to Dashboard
										</Link>
									</div>
								)}

							</div>
						</motion.div>
					</div>
				</div>
			</section>

			{/* Stats Section */}
			<section className="py-16 bg-white">
				<div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
					<div className="grid grid-cols-2 md:grid-cols-4 gap-8">
						{stats.map((stat, index) => (
							<motion.div
								key={index}
								initial={{ opacity: 0, y: 20 }}
								animate={{ opacity: 1, y: 0 }}
								transition={{ delay: index * 0.1 }}
								className="text-center">
								<div className="text-3xl md:text-4xl font-bold text-blue-600 mb-2">
									{stat.number}
								</div>
								<div className="text-gray-600">{stat.label}</div>
							</motion.div>
						))}
					</div>
				</div>
			</section>

			{/* Features Section */}
			<section className="py-20 bg-gray-50">
				<div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
					<div className="text-center mb-16">
						<h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
							Our Services
						</h2>
						<p className="text-xl text-gray-600 max-w-3xl mx-auto">
							Comprehensive services designed to enhance your university
							experience
						</p>
					</div>

					<div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
						{features.map((feature, index) => (
							<motion.div
								key={index}
								initial={{ opacity: 0, y: 20 }}
								animate={{ opacity: 1, y: 0 }}
								transition={{ delay: index * 0.1 }}
								className="bg-white rounded-2xl p-6 shadow-sm hover:shadow-lg transition-shadow group">
								<div className="w-12 h-12 bg-blue-100 rounded-xl flex items-center justify-center mb-4 group-hover:bg-blue-600 transition-colors">
									<feature.icon className="w-6 h-6 text-blue-600 group-hover:text-white transition-colors" />
								</div>
								<h3 className="text-xl font-semibold text-gray-900 mb-3">
									{feature.title}
								</h3>
								<p className="text-gray-600 mb-4">{feature.description}</p>
								<Link
									to={feature.link}
									className="inline-flex items-center text-blue-600 hover:text-blue-700 font-medium">
									Learn More
									<ArrowRight className="w-4 h-4 ml-1" />
								</Link>
							</motion.div>
						))}
					</div>
				</div>
			</section>

			{/* Announcements Section */}
			<section className="py-20 bg-white">
				<div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
					<div className="flex items-center justify-between mb-12">
						<h2 className="text-3xl md:text-4xl font-bold text-gray-900">
							Latest Announcements
						</h2>
						<Link
							to="/latest"
							className="text-blue-600 hover:text-blue-700 font-medium">
							View All
						</Link>
					</div>

					<div className="grid grid-cols-1 md:grid-cols-3 gap-6">
						{announcements.map((announcement, index) => (
							<motion.div
								key={announcement.id}
								initial={{ opacity: 0, y: 20 }}
								animate={{ opacity: 1, y: 0 }}
								transition={{ delay: index * 0.1 }}
								className={`bg-gray-50 rounded-xl p-6 hover:shadow-md transition-shadow ${
									announcement.urgent ? "border-l-4 border-red-500" : ""
								}`}>
								{announcement.urgent && (
									<span className="inline-block bg-red-100 text-red-800 text-xs px-2 py-1 rounded-full mb-3">
										Urgent
									</span>
								)}
								<h3 className="text-lg font-semibold text-gray-900 mb-2">
									{announcement.title}
								</h3>
								<p className="text-sm text-gray-500">
									{new Date(announcement.date).toLocaleDateString()}
								</p>
							</motion.div>
						))}
					</div>
				</div>
			</section>

			{/* CTA Section */}
			<section className="py-20 bg-gradient-to-r from-blue-700 to-blue-500 text-white">
				<div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
					<h2 className="text-3xl md:text-4xl font-bold mb-4">
						Join the Student Union Community
					</h2>
					<p className="text-xl text-blue-100 mb-8 max-w-3xl mx-auto">
						Make your voice heard, drive change, and enhance your university
						experience
					</p>
					{!user && (
						<Link
							to="/login"
							className="bg-white text-blue-700 px-8 py-4 rounded-xl font-semibold hover:bg-blue-50 transition-colors inline-flex items-center">
							Get Started Today
							<ArrowRight className="w-5 h-5 ml-2" />
						</Link>
					)}
				</div>
			</section>
		</div>
	);
};
