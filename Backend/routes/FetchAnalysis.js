const express = require("express");
const fs = require("fs");
const path = require("path");

const router = express.Router();

// ✅ API to Fetch Analysis Result from result.json
router.get("/", (req, res) => {
  const resultFilePath = path.join(__dirname, "../Ransom-ware/Analysis_report/result.json");

  fs.readFile(resultFilePath, "utf8", (err, data) => {
    if (err) {
      console.error("❌ Error reading result.json:", err);
      return res.status(500).json({ error: "Failed to read analysis result." });
    }

    try {
      const result = JSON.parse(data);
      res.json(result);
    } catch (parseError) {
      console.error("❌ JSON Parse Error:", parseError);
      res.status(500).json({ error: "Invalid JSON format in result.json" });
    }
  });
});

module.exports = router;
