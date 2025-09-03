import React from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../../contexts/AuthContext";

export function AdminRoute({ children }) {
  const { user, adminCredential } = useAuth();

  if (!user || !user.isAdmin || !adminCredential) {
    return <Navigate to="/dashboard" replace />;
  }

  return children;
}