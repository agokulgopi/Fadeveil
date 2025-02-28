const express = require("express");
const fs = require("fs");
const path = require("path");

const router = express.Router();

// Directory where uploaded files are stored
const UPLOADS_DIR = path.join(__dirname, "..", "uploads");

// Fetch list of uploaded files
router.get("/uploads", (req, res) => {
  fs.readdir(UPLOADS_DIR, (err, files) => {
    if (err) {
      return res.status(500).json({ error: "Failed to retrieve files" });
    }
    res.json(files);
  });
});

// Handle file download and delete after sending
router.get("/download/:filename", (req, res) => {
  const filePath = path.join(UPLOADS_DIR, req.params.filename);
  if (fs.existsSync(filePath)) {
    res.download(filePath, (err) => {
      if (err) {
        console.error("Error sending file:", err);
        res.status(500).json({ error: "Failed to download file" });
      } else {
        // Delete file after successful download
        fs.unlink(filePath, (unlinkErr) => {
          if (unlinkErr) {
            console.error("Error deleting file:", unlinkErr);
          } else {
            console.log(`File ${req.params.filename} deleted successfully`);
          }
        });
      }
    });
  } else {
    res.status(404).json({ error: "File not found" });
  }
});

module.exports = router;
