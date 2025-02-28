const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const RegisteredUser = require("../models/Users");

const router = express.Router();

// User Login Route
router.post("/login", async (req, res) => {
  console.log("📥 Incoming Login Request:", req.body);

  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      console.log("❌ Missing Fields");
      return res.status(400).json({ success: false, message: "All fields are required." });
    }

    // Check if user exists
    const user = await RegisteredUser.findOne({ email });
    if (!user) {
      console.log("❌ User Not Found:", email);
      return res.status(400).json({ success: false, message: "Invalid credentials." });
    }

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.log("❌ Incorrect Password:", email);
      return res.status(400).json({ success: false, message: "Invalid credentials." });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user._id, name: user.name, role: user.role },
      process.env.JWT_SECRET || "your_jwt_secret",
      { expiresIn: "1h" }
    );

    console.log("✅ Login Successful:", { email, role: user.role });

    // ✅ Role-based response
    res.status(200).json({
      success: true,
      message: "Login successful!",
      token,
      role: user.role,  // ✅ Added role in response
      user: { name: user.name, email: user.email, role: user.role },
    });

  } catch (error) {
    console.error("❌ Server Error:", error.message);
    res.status(500).json({ success: false, message: "Server error", error: error.message });
  }
});

module.exports = router;
