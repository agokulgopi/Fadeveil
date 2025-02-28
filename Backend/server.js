const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { exec } = require("child_process");

dotenv.config();
const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.error("MongoDB Connection Error:", err));

// User Model
const User = mongoose.model("User", new mongoose.Schema({
  email: String,
  password: String,
  role: String // "Cyber Researcher" or "Incident Responder"
}));

// Login Route (Handles Role-based Navigation)
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

    // Generate JWT Token
    const token = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ message: "Login successful", token, role: user.role });
  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// Import Routes
const registerRoute = require("./routes/register");
const uploadRoute = require("./routes/FileUpload");
const analysisRoute = require("./routes/FileAnalysis");
const fetchAnalysisRoute = require("./routes/FetchAnalysis");
const fetchDownloadRoutes = require("./routes/FetchDownload");
// Use Routes
app.use("/api", registerRoute);
app.use("/api/upload", uploadRoute);
app.use("/api/analyze", analysisRoute);
app.use("/api/fetch-analysis", fetchAnalysisRoute);

// Serve uploaded files statically
app.use("/uploads", express.static("uploads"));


app.use("/api", fetchDownloadRoutes);

// API to fetch list of files from the 'uploads' folder
app.get("/api/files", (req, res) => {
  const UPLOADS_DIR = path.join(__dirname, "uploads");

  fs.readdir(UPLOADS_DIR, (err, files) => {
    if (err) {
      return res.status(500).json({ error: "Error reading uploads directory" });
    }

    const fileDetails = files.map((file, index) => ({
      id: index + 1,
      name: file,
    }));

    res.json(fileDetails);
  });
});

// API to Execute `AnalysisReport.py`
app.post("/api/analyze", (req, res) => {
  const scriptPath = path.join(__dirname, "Ransom-ware", "Analysis_report", "AnalysisReport.py");

  const pythonPaths = [
    // "C:\\Users\\manik\\AppData\\Local\\Programs\\Python\\Python310\\python.exe",
    // "C:\\Users\\manik\\AppData\\Local\\Programs\\Python\\Python312\\python.exe",
    // "C:\\Users\\manik\\AppData\\Local\\Microsoft\\WindowsApps\\python.exe",
    // "python3",
    // "python",
    "C:\\Users\\undak\\AppData\\Local\\Programs\\Python\\Python310\\python.exe",
    "C:\\Users\\undak\\AppData\\Local\\Microsoft\\WindowsApps\\python.exe",
    "C:\\msys64\\ucrt64\\bin\\python.exe",
    "python3",
    "python",
  ];

  let pythonCommand = pythonPaths.find((p) => fs.existsSync(p)) || "python";

  exec(`${pythonCommand} ${scriptPath}`, (error, stdout, stderr) => {
    if (error) {
      console.error(`Error executing script: ${error.message}`);
      return res.status(500).json({ error: error.message });
    }
    if (stderr) {
      console.error(`Script Error: ${stderr}`);
      return res.status(500).json({ error: stderr });
    }

    try {
      const outputJson = JSON.parse(stdout.trim());
      return res.json(outputJson);
    } catch (parseError) {
      console.error("JSON Parse Error:", parseError);
      return res.status(500).json({ error: "Invalid JSON response from script" });
    }
  });
});

// API to Execute `decrypter.py` for ALL files
app.post("/api/decrypt", async (req, res) => {
  const UPLOADS_DIR = path.join(__dirname, "uploads");

  if (!fs.existsSync(UPLOADS_DIR)) {
    return res.status(404).json({ error: "Uploads directory not found" });
  }

  const scriptPath = path.join(__dirname, "Ransom-ware", "decrypter", "decrypter.py");

  const pythonPaths = [
    // "C:\\Users\\manik\\AppData\\Local\\Programs\\Python\\Python310\\python.exe",
    // "C:\\Users\\manik\\AppData\\Local\\Programs\\Python\\Python312\\python.exe",
    // "C:\\Users\\manik\\AppData\\Local\\Microsoft\\WindowsApps\\python.exe",
    // "python3",
    // "python",
    "C:\\Users\\undak\\AppData\\Local\\Programs\\Python\\Python310\\python.exe",
    "C:\\Users\\undak\\AppData\\Local\\Microsoft\\WindowsApps\\python.exe",
    "C:\\msys64\\ucrt64\\bin\\python.exe",
    "python3",
    "python",
  ];

  let pythonCommand = pythonPaths.find((p) => fs.existsSync(p)) || "python";

  fs.readdir(UPLOADS_DIR, (err, files) => {
    if (err) return res.status(500).json({ error: "Error reading uploads directory" });

    if (files.length === 0) return res.status(400).json({ error: "No files found for decryption" });

    let decryptedFiles = [];
    let errors = [];

    const decryptFile = (file) => {
      return new Promise((resolve) => {
        const filePath = path.join(UPLOADS_DIR, file);

        exec(`${pythonCommand} ${scriptPath} "${filePath}"`, (error, stdout, stderr) => {
          if (error) {
            console.error(`Decryption Error for ${file}: ${error.message}`);
            errors.push({ file, error: error.message });
          } else if (stderr) {
            console.error(`Decryption Script Error for ${file}: ${stderr}`);
            errors.push({ file, error: stderr });
          } else {
            console.log(`Decryption Successful for ${file}`);
            decryptedFiles.push({ file, message: stdout.trim() });
          }
          resolve();
        });
      });
    };

    Promise.all(files.map(decryptFile)).then(() => {
      res.json({
        success: true,
        message: "Decryption process completed",
        decryptedFiles,
        errors,
      });
    });
  });
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
