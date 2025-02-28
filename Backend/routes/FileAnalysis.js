const express = require("express");
const { exec } = require("child_process");
const path = require("path");

const router = express.Router();

// Python paths to check
const pythonPaths = [
    // `"C:\\Users\\manik\\AppData\\Local\\Programs\\Python\\Python310\\python.exe"`,
    // `"C:\\Users\\manik\\AppData\\Local\\Programs\\Python\\Python312\\python.exe"`,
    // `"C:\\Users\\manik\\AppData\\Local\\Microsoft\\WindowsApps\\python.exe"`
    `"C:\\Users\\undak\\AppData\\Local\\Programs\\Python\\Python310\\python.exe"`,
    `"C:\\Users\\undak\\AppData\\Local\\Microsoft\\WindowsApps\\python.exe"`,
    `"C:\\msys64\\ucrt64\\bin\\python.exe"`
];

// Define API to execute AnalysisReport.py
router.get("/analyze", (req, res) => {
    const scriptPath = path.join(__dirname, "../Ransom-ware/Analysis_report/AnalysisReport.py");

    // Try executing with each Python path until one works
    const tryPython = (index) => {
        if (index >= pythonPaths.length) {
            return res.status(500).json({ error: "No valid Python executable found." });
        }

        const command = `${pythonPaths[index]} ${scriptPath}`;
        exec(command, (error, stdout, stderr) => {
            if (error) {
                console.error(`❌ Error executing with ${pythonPaths[index]}: ${error.message}`);
                return tryPython(index + 1); // Try next Python path
            }
            if (stderr) {
                console.error(`⚠️ Script stderr: ${stderr}`);
                return res.status(500).json({ error: stderr });
            }

            console.log(`✅ Script executed successfully with ${pythonPaths[index]}`);
            res.json({ message: "Analysis Completed", output: stdout });
        });
    };

    tryPython(0); // Start with the first Python path
});

module.exports = router;
