const express = require("express");
const bcrypt = require("bcryptjs");
const RegisteredUser = require("../models/Users");

const router = express.Router();

// Register User
router.post("/register", async (req, res) => {
  console.log("📥 Incoming Registration Request:", req.body);

  try {
    const { name, email, password, role } = req.body;

    // Validate input fields
    if (!name || !email || !password || !role) {
      console.log("❌ Missing Fields");
      return res.status(400).json({ success: false, message: "All fields are required." });
    }

    // Check if user already exists
    const existingUser = await RegisteredUser.findOne({ email });
    if (existingUser) {
      console.log("❌ User Already Exists:", email);
      return res.status(400).json({ success: false, message: "User already exists." });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Save new user
    const newUser = new RegisteredUser({
      name,
      email,
      password: hashedPassword, // Store hashed password securely
      role,
    });

    await newUser.save();

    console.log("✅ User Registered Successfully:", { name, email, role });

    res.status(201).json({ 
      success: true, 
      message: "User registered successfully!",
      user: { name, email, role } // Do not send password
    });

  } catch (error) {
    console.error("❌ Server Error:", error.message);
    res.status(500).json({ success: false, message: "Server error", error: error.message });
  }
});

module.exports = router;
