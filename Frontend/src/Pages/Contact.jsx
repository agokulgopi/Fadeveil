import React from 'react';
import NavBar from '../Components/NavBar.jsx';
import aboutVideo from '../Images/contact.mp4'; // Importing the video file
import '../About.css';

const Contact = () => {
  return (
    <div className="About">
      <NavBar />

      {/* Video Section */}
      <div className="video-container">
        <video className="about-video" autoPlay loop muted playsInline>
          <source src={aboutVideo} type="video/mp4" />
          Your browser does not support the video tag.
        </video>
      </div>

      <div className="content">
        <div className="description">
          <h1>Fadeveil: A Ransomware Analysis and Decryption System</h1>
          <p>
            Fadeveil is a ransomware analysis and decryption tool designed to detect, analyze, and mitigate ransomware attacks without requiring victims to pay a ransom.
          </p>
        </div>
      </div>
    </div>
  );
};

export default Contact;
