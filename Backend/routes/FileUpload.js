const express = require("express");
const multer = require("multer");
const crypto = require("crypto"); // For hashing file integrity
const path = require("path");
const fs = require("fs");

const router = express.Router();

// Ensure uploads directory exists
const uploadDir = path.join(__dirname, "..", "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

// Set up storage for Multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});

// Multer configuration for multiple files
const upload = multer({ storage }).array("files", 10); // Max 10 files

// Hash function to verify file integrity
const getFileHash = (filePath) => {
  const hash = crypto.createHash("sha256");
  const fileBuffer = fs.readFileSync(filePath);
  hash.update(fileBuffer);
  return hash.digest("hex");
};

// File Upload API
router.post("/", (req, res) => {
  upload(req, res, (err) => {
    if (err) {
      return res.status(500).json({ error: "File upload failed", details: err.message });
    }

    // Generate file metadata (including hash for integrity check)
    const fileUrls = req.files.map((file) => ({
      filename: file.filename,
      originalName: file.originalname,
      path: `/uploads/${file.filename}`,
      hash: getFileHash(file.path), // Hash for integrity check
    }));

    res.json({
      message: "Files uploaded successfully, Login after 10 minutes",
      files: fileUrls,
    });
  });
});

module.exports = router;
