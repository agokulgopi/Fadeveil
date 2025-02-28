const mongoose = require("mongoose");

// User Schema
const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
  },
  password: {
    type: String,
    required: true,
    minlength: 6, // Increased for better security
  },
  role: {
    type: String,
    required: true,
    enum: ["Cyber Researcher", "Incident Responder"], // Ensures only valid roles are stored
  },
  createdAt: {
    type: Date,
    default: Date.now, // Automatically adds a timestamp when a user is created
  },
});

// ✅ Fix: Prevent model overwrite
const RegisteredUser = mongoose.models.User || mongoose.model("User", UserSchema);

module.exports = RegisteredUser;
