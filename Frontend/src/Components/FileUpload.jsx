import React, { useState } from "react";
import axios from "axios";

const FileUpload = () => {
  const [progress, setProgress] = useState({});
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [decryptedFiles, setDecryptedFiles] = useState([]); // Store decrypted file URLs

  // Handle file selection
  const handleFileChange = (event) => {
    setSelectedFiles([...event.target.files]);
    setProgress({});
  };

  // Handle file upload
  const handleUpload = async () => {
    if (selectedFiles.length === 0) {
      alert("Please select at least one file.");
      return;
    }

    const formData = new FormData();
    selectedFiles.forEach((file) => formData.append("files", file));

    try {
      const response = await axios.post("http://localhost:5000/api/upload", formData, {
        headers: { "Content-Type": "multipart/form-data" },
        onUploadProgress: (progressEvent) => {
          const percentCompleted = Math.round((progressEvent.loaded * 100) / progressEvent.total);
          setProgress((prevProgress) => ({ ...prevProgress, overall: percentCompleted }));
        },
      });

      alert("Files uploaded successfully! Login after 10 minutes.");
      console.log("Uploaded Files:", response.data);
      setSelectedFiles([]);
      setProgress({ overall: 100 });

      // Simulating decrypted files list (replace this with actual response from backend)
      setDecryptedFiles(response.data.decryptedFiles || []);
      
    } catch (error) {
      console.error("Error uploading files:", error);
      alert("File upload failed.");
    }
  };

  // Handle file download
  const handleDownload = (fileUrl) => {
    const link = document.createElement("a");
    link.href = fileUrl;
    link.download = fileUrl.split("/").pop();
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="main">
      <div className="container">
        <div className="infoText">
          <h2>Upload your Encrypted files</h2>
        </div>
        <div className="fileContainer">
          <div className="fileInput">
            <input type="file" multiple onChange={handleFileChange} />
            <button onClick={handleUpload}>Upload Files</button>
          </div>

          {/* Progress Bar */}
          {progress.overall > 0 && (
            <div className="progressWrapper">
              <div className="progressBar">
                <div className="progressFill" style={{ width: `${progress.overall}%` }}></div>
              </div>
              <span className="progressText">{progress.overall || 0}%</span>
            </div>
          )}

          {/* Selected Files */}
          {selectedFiles.length > 0 && (
            <div className="fileList">
              <h3>Selected Files:</h3>
              <ul>
                {selectedFiles.map((file, index) => (
                  <li key={index}>{file.name}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Decrypted Files - Download Section */}
          {decryptedFiles.length > 0 && (
            <div className="fileList">
              <h3>Decrypted Files:</h3>
              <ul>
                {decryptedFiles.map((fileUrl, index) => (
                  <li key={index}>
                    {fileUrl.split("/").pop()} {/* Display only the file name */}
                    <button className="downloadBtn" onClick={() => handleDownload(fileUrl)}>
                      Download
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default FileUpload;
