import React from "react";
import Navbar from "./Navbar.jsx";
import videoFile from "../Images/workflow2.mp4"; // Ensure the correct path

const WorkFlow = () => {
  return (
    <div style={styles.workflowPage}>
      {/* Navbar */}
      <Navbar />

      {/* Video Section */}
      <div style={styles.videoContainer}>
        <video autoPlay loop muted playsInline style={styles.backgroundVideo}>
          <source src={videoFile} type="video/mp4" />
          Your browser does not support the video tag.
        </video>
      </div>
    </div>
  );
};

// Inline Styles
const styles = {
  workflowPage: {
    width: "100%",
    height: "100vh",
    display: "flex",
    flexDirection: "column",
  },
  videoContainer: {
    flexGrow: 1, // Makes video take remaining space after Navbar
    width: "100%",
    overflow: "hidden",
  },
  backgroundVideo: {
    width: "100%",
    height: "100%",
    objectFit: "cover",
  },
};

export default WorkFlow;
