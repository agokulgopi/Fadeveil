const express = require("express");
const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

const router = express.Router();

// Path to the Python decryption script
const decryptScriptPath = path.join(__dirname, "../Ransom-ware/decrypter/decrypter.py");

// Determine the correct Python command
const pythonPaths = ["python3", "python"];
const pythonCommand = pythonPaths.find((cmd) => {
  try {
    require("child_process").execSync(`${cmd} --version`);
    return true;
  } catch (e) {
    return false;
  }
}) || "python";

router.post("/decrypt", async (req, res) => {
  try {
    console.log("🔹 Decryption process started...");

    // Get the filename from request body
    const { filename } = req.body;
    if (!filename) {
      return res.status(400).json({ success: false, error: "Filename is required!" });
    }

    // Check if file exists
    const filePath = path.join(__dirname, "../uploads", filename);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ success: false, error: "File not found!" });
    }

    // Spawn the Python process with the file path as an argument
    const pythonProcess = spawn(pythonCommand, [decryptScriptPath, filePath]);

    let output = "";
    let errorOutput = "";

    pythonProcess.stdout.on("data", (data) => {
      output += data.toString();
      console.log("🔹 Python Output:", data.toString().trim());
    });

    pythonProcess.stderr.on("data", (data) => {
      errorOutput += data.toString();
      console.error("❌ Python Error:", data.toString().trim());
    });

    pythonProcess.on("close", (code) => {
      if (code === 0) {
        console.log("✅ Decryption completed successfully!");
        res.json({ success: true, message: "Decryption completed successfully!", details: output.trim() });
      } else {
        console.error("❌ Decryption failed!", errorOutput);
        res.status(500).json({ success: false, error: "Decryption failed!", details: errorOutput.trim() });
      }
    });

  } catch (error) {
    console.error("⚠️ Internal Server Error:", error);
    res.status(500).json({ success: false, error: "Internal server error!" });
  }
});

module.exports = router;
