import React from "react";
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import { Toaster } from "react-hot-toast";
import { AuthProvider, useAuth } from "./contexts/AuthContext";
import { Layout } from "./components/Layout/Layout";
import { ProtectedRoute } from "./components/Auth/ProtectedRoute";
import { AdminRoute } from "./components/Auth/AdminRoute";
import { LoginForm } from "./components/Auth/LoginForm";
import { Home } from "./components/Pages/Home";
import { Clubs } from "./components/Pages/Clubs";
import { Elections } from "./components/Pages/Elections";
import { Services } from "./components/Pages/Services";
import { Latest } from "./components/Pages/Latest";
import { Complaints } from "./components/Pages/Complaints";
import { Dashboard } from "./components/Dashboard/Dashboard";
import { AdminDashboard } from "./components/Admin/AdminDashboard";
import { About } from "./components/Pages/About";
import { Contact } from "./components/Pages/Contact";
import "./index.css";

function AppContent() {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <div className="w-16 h-16 border-4 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-gray-600">Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <Router>
      <Layout>
        <Routes>
          {/* Public Routes */}
          <Route path="/" element={<Home />} />
          <Route path="/about" element={<About />} />
          <Route path="/contact" element={<Contact />} />
          
          {/* Auth Route */}
          <Route
            path="/login"
            element={
              user ? (
                <Navigate to="/dashboard" replace />
              ) : (
                <LoginForm />
              )
            }
          />

          {/* Protected Routes */}
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            }
          />

          <Route
            path="/clubs"
            element={
              <ProtectedRoute>
                <Clubs />
              </ProtectedRoute>
            }
          />

          <Route
            path="/elections"
            element={
              <ProtectedRoute>
                <Elections />
              </ProtectedRoute>
            }
          />

          <Route
            path="/services"
            element={
              <ProtectedRoute>
                <Services />
              </ProtectedRoute>
            }
          />

          <Route
            path="/latest"
            element={
              <ProtectedRoute>
                <Latest />
              </ProtectedRoute>
            }
          />

          <Route
            path="/complaints"
            element={
              <ProtectedRoute>
                <Complaints />
              </ProtectedRoute>
            }
          />

          {/* Admin Routes */}
          <Route
            path="/admin"
            element={
              <ProtectedRoute>
                <AdminRoute>
                  <AdminDashboard />
                </AdminRoute>
              </ProtectedRoute>
            }
          />

          {/* Fallback Route */}
          <Route 
            path="*" 
            element={
              user ? <Navigate to="/dashboard" replace /> : <Navigate to="/" replace />
            } 
          />
        </Routes>
      </Layout>
      
      <Toaster
        position="top-right"
        toastOptions={{
          duration: 4000,
          style: {
            background: "#363636",
            color: "#fff",
          },
        }}
      />
    </Router>
  );
}

export function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}

export default App;