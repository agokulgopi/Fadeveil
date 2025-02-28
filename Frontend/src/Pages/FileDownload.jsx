import React, { useEffect, useState } from "react";
import axios from "axios";
import "./FileDownload.css"; 
import NavBar from "../Components/NavBar"; 

const FileDownload = () => {
  const [files, setFiles] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    axios
      .get("http://localhost:5000/api/uploads") 
      .then((response) => setFiles(response.data))
      .catch(() => setError("Failed to fetch files"));
  }, []);

  const handleDownloadAll = () => {
    files.forEach((file) => {
      if (!file.endsWith(".wcry")) {
        axios({
          url: `http://localhost:5000/api/download/${file}`,
          method: "GET",
          responseType: "blob",
        })
          .then((response) => {
            const url = window.URL.createObjectURL(new Blob([response.data]));
            const link = document.createElement("a");
            link.href = url;
            link.setAttribute("download", file);
            document.body.appendChild(link);
            link.click();
            link.remove();
          })
          .catch(() => setError(`Failed to download ${file}`));
      }
    });
  };

  // Check if any file is encrypted
  const isAnyEncrypted = files.some((file) => file.endsWith(".wcry"));

  return (
    <div>
      <NavBar />
      
      <div className="file-download-container">
        <div className="content">
          <h2 className="title">Download Files <hr /> </h2>
          {error && <p className="text-red-500">{error}</p>}
          <div className="file-list">
            {files.map((file, index) => (
              <div key={index} className="file-item">
                <span className="file-name">{file}</span>
              </div>
            ))}
          </div>
          <div className="download-button">
            <button className="btn" onClick={handleDownloadAll} disabled={isAnyEncrypted}>
              {isAnyEncrypted ? "Encrypted" : "Download All"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default FileDownload;
