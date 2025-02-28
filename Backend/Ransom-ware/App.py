from flask import Flask, jsonify, request
import subprocess
import os
import json

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Route to get list of uploaded files
@app.route('/api/files', methods=['GET'])
def get_files():
    try:
        files = os.listdir(UPLOAD_FOLDER)
        return jsonify([{"name": file} for file in files])
    except Exception as e:
        return jsonify({"error": "Failed to retrieve files", "details": str(e)}), 500

# Route to trigger analysis
@app.route('/analyze', methods=['POST'])
def run_analysis():
    try:
        # Path to AnalysisReport.py
        script_path = os.path.join(os.getcwd(), "Analysis_report", "AnalysisReport.py")
        
        if not os.path.exists(script_path):
            return jsonify({"error": "Analysis script not found"}), 404
        
        # Run the Python script and capture output
        result = subprocess.run(["python", script_path], capture_output=True, text=True)

        # Check if the script executed successfully
        if result.returncode == 0:
            try:
                output_json = json.loads(result.stdout.strip())  # Ensure valid JSON
                return jsonify(output_json)
            except json.JSONDecodeError:
                return jsonify({"error": "Invalid JSON response from script"}), 500
        else:
            return jsonify({"error": "Analysis failed", "details": result.stderr}), 500

    except Exception as e:
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
