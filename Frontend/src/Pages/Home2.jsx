import React, { useState, useEffect } from "react";
import "../Style.scss";
import NavBar from "../Components/Navbar";

const Home2 = () => {
  const [files, setFiles] = useState([]);
  const [analysisData, setAnalysisData] = useState([]);
  const [loading, setLoading] = useState(false);
  const [showDecryptButton, setShowDecryptButton] = useState(false);

  useEffect(() => {
    const fetchFiles = async () => {
      try {
        const response = await fetch("http://localhost:5000/api/files");
        const data = await response.json();
        setFiles(data);
      } catch (error) {
        console.error("Error fetching files:", error);
      }
    };
    fetchFiles();
  }, []);

  const handleAnalysis = async () => {
    if (files.length === 0) {
      alert("No files available for analysis.");
      return;
    }

    setLoading(true);
    try {
      const response = await fetch("http://localhost:5000/api/analyze", {
        method: "POST",
      });

      const data = await response.json();
      if (data.error) {
        alert("Error: " + data.error);
      } else {
        alert("Analysis completed successfully!");

        const resultResponse = await fetch("http://localhost:5000/api/fetch-analysis");
        const resultData = await resultResponse.json();
        setAnalysisData(resultData);
        setShowDecryptButton(true); // Show decryption button after analysis
      }
    } catch (error) {
      console.error("Error running analysis:", error);
      alert("Failed to run analysis.");
    }
    setLoading(false);
  };

  const handleDecryption = async () => {
    try {
      const response = await fetch("http://localhost:5000/api/decrypt", {
        method: "POST",
      });

      const data = await response.json();
      if (data.error) {
        alert("Error: " + data.error);
      } else {
        alert("Decryption completed successfully!");
      }
    } catch (error) {
      console.error("Error during decryption:", error);
      alert("Failed to decrypt files.");
    }
  };

  return (
    <>
      <NavBar />
      <div className="content-screen">
        <div className="analysis">
          <table className="custom-table">
            <thead>
              <tr>
                <th>Slno</th>
                <th>Filename</th>
              </tr>
            </thead>
            <tbody>
              {files.length > 0 ? (
                files.map((file, index) => (
                  <tr key={index}>
                    <td>{index + 1}</td>
                    <td>{file.name}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="2">No files available</td>
                </tr>
              )}
            </tbody>
          </table>
          <div className="analysisbtn-container">
            <button className="analysisbtn" onClick={handleAnalysis} disabled={loading}>
              {loading ? "Analyzing..." : "Analyze All Files"}
            </button>
          </div>
        </div>

        {analysisData.length > 0 ? (
          <div className="report">
            <h3>Analysis Results</h3>
            <table className="custom-table">
              <thead>
                <tr>
                  <th>Filename</th>
                  <th>Size</th>
                  <th>Extension</th>
                  <th>MIME Type</th>
                  <th>Entropy</th>
                  <th>Ransomware</th>
                  <th>Encryption Standard</th>
                  <th>Is Encrypted</th>
                </tr>
              </thead>
              <tbody>
                {analysisData.map((file, index) => (
                  <tr key={index}>
                    <td>{file.name}</td>
                    <td>{file.size}</td>
                    <td>{file.extension}</td>
                    <td>{file.mimeType}</td>
                    <td>{file.entropy}</td>
                    <td>{file.ransomware}</td>
                    <td>{file.encryption}</td>
                    <td>{file.isEncrypted}</td>
                  </tr>
                ))}
              </tbody>
            </table>

            {showDecryptButton && (
              <div className="center-container">
                <button className="decryptbtn" onClick={handleDecryption}>
                Apply Decryption
                </button>
              </div>
              
            )}
          </div>
        ) : (
          <p>No analysis results available.</p>
        )}
      </div>
    </>
  );
};

export default Home2;
