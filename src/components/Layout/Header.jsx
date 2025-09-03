/** @format */

import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Menu, X, User, LogOut } from "lucide-react";
import { useAuth } from "../../contexts/AuthContext";
import "../../app.css";

export function Header() {
	const [isMenuOpen, setIsMenuOpen] = useState(false);
	const { user, logout } = useAuth();
	const navigate = useNavigate();

	const handleLogout = () => {
		logout();
		navigate("/");
	};

	const navigation = [
		...(user ? [] : [
			{ name: "Home", href: "/" },
			{ name: "About", href: "/about" },
			{ name: "Contact", href: "/contact" },
		]),
	];

	const protectedNavigation = [
		...(user ? [
			{ name: "Dashboard", href: "/dashboard" },
			{ name: "Clubs", href: "/clubs" },
			{ name: "Elections", href: "/elections" },
			{ name: "Services", href: "/services" },
			{ name: "Latest", href: "/latest" },
			{ name: "Complaints", href: "/complaints" },
		] : []),
	];

	return (
		<header className="bg-white shadow-sm border-b border-gray-200">
			{/* Top Info Bar */}
			<div className="bg-blue  hidden sm:flex text-white py-2 text-sm">
				<div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
					<div className="flex justify-between items-center">
						<div className="flex space-x-6">
							<span>
								<i className="fas fa-map-marker-alt p-2"></i> DBU Campus,
								Student Union Building
							</span>
							<span>
								<i className="fas fa-envelope p-2"></i> studentunion@dbu.edu.et
							</span>
							<span>
								<i className="fas fa-phone p-2"></i> +251940414243
							</span>
						</div>
						<div className="flex space-x-3">
							<a href="#" className="hover:text-blue-200">
								<i className="fab fa-facebook"></i>
							</a>
							<a href="#" className="hover:text-blue-200">
								<i className="fab fa-telegram"></i>
							</a>
							<a href="#" className="hover:text-blue-200">
								<i className="fab fa-instagram"></i>
							</a>
							<a href="#" className="hover:text-blue-200">
								<i className="fab fa-tiktok"></i>
							</a>
						</div>
					</div>
				</div>
			</div>

			{/* Logo */}
			<div>
				<div className="w-full h-auto">
					<img
						src="/images/logo.png" // Replace with your image URL
						alt="Logo"
						className="w-full h-auto object-cover"
					/>
				</div>
				<hr />
			</div>

			{/* Main Header */}
			<div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
				<div className="flex justify-between items-center py-4">
					{/* Desktop Navigation */}
					<nav className="hidden md:flex space-x-8">
						{navigation.map((item) => (
							<Link
								key={item.name}
								to={item.href}
								className="text-gray-700 hover:text-blue-600 font-medium transition-colors">
								{item.name}
							</Link>
						))}
						{user &&
							protectedNavigation.map((item) => (
								<Link
									key={item.name}
									to={item.href}
									className="text-gray-700 hover:text-blue-600 font-medium transition-colors">
									{item.name}
								</Link>
							))}
					</nav>

					{/* User Menu */}
					<div className="flex items-center space-x-4">
						{user ? (
							<div className="flex items-center space-x-3">
								<div className="flex items-center space-x-2 text-gray-700">
									<User className="w-5 h-5" />
									<span className="hidden sm:inline">{user.name}</span>
									{user.isAdmin && (
										<span className="bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded-full">
											Admin
										</span>
									)}
								</div>
								{user.isAdmin && (
									<Link
										to="/admin"
										className="bg-blue-600 text-white px-3 py-1 rounded-lg text-sm hover:bg-blue-700 transition-colors">
										Admin Panel
									</Link>
								)}
								<button
									onClick={handleLogout}
									className="flex items-center space-x-2 text-gray-700 hover:text-red-600">
									<LogOut className="w-5 h-5" />
									<span className="hidden sm:inline">Logout</span>
								</button>
							</div>
						) : (
							<Link
								to="/login"
								className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors">
								Login
							</Link>
						)}

						{/* Mobile menu button */}
						<button
							aria-label="Toggle menu"
							onClick={() => setIsMenuOpen(!isMenuOpen)}
							className="md:hidden p-2 rounded-md text-gray-700 hover:text-blue-600">
							{isMenuOpen ? (
								<X className="w-6 h-6" />
							) : (
								<Menu className="w-6 h-6" />
							)}
						</button>
					</div>
				</div>
			</div>

			{/* Mobile Navigation */}
			{isMenuOpen && (
				<div className="md:hidden bg-white border-t border-gray-200">
					<div className="px-4 py-2 space-y-1">
						{navigation.map((item) => (
							<Link
								key={item.name}
								to={item.href}
								className="block px-3 py-2 text-gray-700 hover:text-blue-600 hover:bg-gray-50 rounded-md"
								onClick={() => setIsMenuOpen(false)}>
								{item.name}
							</Link>
						))}
						{user &&
							protectedNavigation.map((item) => (
								<Link
									key={item.name}
									to={item.href}
									className="block px-3 py-2 text-gray-700 hover:text-blue-600 hover:bg-gray-50 rounded-md"
									onClick={() => setIsMenuOpen(false)}>
									{item.name}
								</Link>
							))}
					</div>
				</div>
			)}
		</header>
	);
}