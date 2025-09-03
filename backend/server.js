/** @format */

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

// Import routes
const authRoutes = require("./routes/auth");
const userRoutes = require("./routes/users");
const complaintRoutes = require("./routes/complaints");
const clubRoutes = require("./routes/clubs");
const electionRoutes = require("./routes/elections");
const postRoutes = require("./routes/posts");
const contactRoutes = require("./routes/contact");

// Import middleware
const errorHandler = require("./middleware/errorHandler");
const { createDefaultAdmin } = require("./utils/createAdmin");

const app = express();

// Security middleware
app.use(helmet());
app.use(
  cors({
    origin:
      process.env.NODE_ENV === "production"
        ? ["https://your-frontend-domain.com"]
        : ["http://localhost:3000", "http://localhost:5173", "http://localhost:8080"],
    credentials: true,
  })
);

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // Increased limit for development
  message: "Too many requests from this IP, please try again later.",
});
app.use("/api/", limiter);

// Body parsing middleware
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// Logging middleware
if (process.env.NODE_ENV === "development") {
  app.use(morgan("dev"));
}

// Static files
app.use("/uploads", express.static("uploads"));

// Health check endpoint
app.get("/health", (req, res) => {
  return res.status(200).json({
    status: "OK",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    database: mongoose.connection.readyState === 1 ? "Connected" : "Disconnected"
  });
});

// API routes
app.use("/api/auth", authRoutes);
app.use("/api/users", userRoutes);
app.use("/api/complaints", complaintRoutes);
app.use("/api/clubs", clubRoutes);
app.use("/api/elections", electionRoutes);
app.use("/api/posts", postRoutes);
app.use("/api/contact", contactRoutes);

// 404 handler
app.use("*", (req, res) => {
  return res.status(404).json({
    success: false,
    message: "Route not found",
    path: req.originalUrl
  });
});

// Error handling middleware - MUST be the last middleware
app.use(errorHandler);

console.log("MongoDB URI:", process.env.MONGODB_URI);

// Database connection with retry logic
const connectDB = async (retries = 5, delay = 5000) => {
  try {
    if (!process.env.MONGODB_URI) {
      throw new Error("MONGODB_URI is not defined in environment variables");
    }

    const conn = await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 30000,
      socketTimeoutMS: 120000,
      connectTimeoutMS: 30000,
      maxPoolSize: 10,
      minPoolSize: 5,
      maxIdleTimeMS: 60000,
      waitQueueTimeoutMS: 10000,
      heartbeatFrequencyMS: 30000,
      retryWrites: true,
      w: 'majority'
    });
    
    console.log(`✅ MongoDB Connected: ${conn.connection.host}`);
    console.log(`✅ Database: ${conn.connection.name}`);

    // Create default admin user
    try {
      await createDefaultAdmin();
    } catch (adminError) {
      console.warn("⚠️ Admin creation warning:", adminError.message);
    }
  } catch (error) {
    console.error(`❌ Database connection error (${retries} retries left):`, error.message);
    
    if (retries > 0) {
      console.log(`🔄 Retrying connection in ${delay/1000} seconds...`);
      setTimeout(() => connectDB(retries - 1, delay), delay);
    } else {
      console.error("❌ Could not connect to MongoDB after multiple attempts");
      process.exit(1);
    }
  }
};

// Start server
const PORT = process.env.PORT || 5000;

const startServer = async () => {
  try {
    await connectDB();

    const server = app.listen(PORT, () => {
      console.log(`✅ Server running on port ${PORT}`);
      console.log(`✅ Environment: ${process.env.NODE_ENV || "development"}`);
      console.log(`✅ Health check: http://localhost:${PORT}/health`);
    });

    // Handle server errors
    server.on('error', (error) => {
      if (error.code === 'EADDRINUSE') {
        console.error(`❌ Port ${PORT} is already in use`);
        process.exit(1);
      } else {
        console.error('❌ Server error:', error);
      }
    });

    // Graceful shutdown
    const gracefulShutdown = (signal) => {
      console.log(`\n🔄 Received ${signal}, shutting down gracefully...`);
      
      server.close(() => {
        console.log("✅ HTTP server closed");
        mongoose.connection.close(false, () => {
          console.log("✅ MongoDB connection closed");
          process.exit(0);
        });
      });

      // Force close after 10 seconds
      setTimeout(() => {
        console.error("❌ Could not close connections in time, forcefully shutting down");
        process.exit(1);
      }, 10000);
    };

    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

  } catch (error) {
    console.error("❌ Failed to start server:", error);
    process.exit(1);
  }
};

// Handle unhandled promise rejections
process.on("unhandledRejection", (err) => {
  console.error("❌ Unhandled Rejection:", err.message);
  console.error(err.stack);
});

// Handle uncaught exceptions
process.on("uncaughtException", (err) => {
  console.error("❌ Uncaught Exception:", err.message);
  console.error(err.stack);
  process.exit(1);
});

// Start the server
startServer();

module.exports = app;