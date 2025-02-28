import React, { useState, useEffect, useRef } from "react";
import "./Timeline.css";
import Navbar from "./Navbar.jsx";

const Timeline = () => {
  const [showNavbar, setShowNavbar] = useState(true);
  const lastScrollY = useRef(window.scrollY);

  useEffect(() => {
    const handleScroll = () => {
      if (window.scrollY > lastScrollY.current) {
        setTimeout(() => setShowNavbar(false), 200); // Delayed hiding
      } else {
        setShowNavbar(true);
      }
      lastScrollY.current = window.scrollY;
    };

    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const events = [
    { date: "March 14th, 2017", title: "Microsoft Security Bulletin", description: "Microsoft released patch MS17-010 for an SMB vulnerability.", color: "red" },
    { date: "March 14th, 2017", title: "Cisco NGFW | Meraki MX", description: "Cisco Talos released Snort™ signature #41978 to detect MS17-010 vulnerabilities.", color: "red" },
    { date: "April 14th, 2017", title: "Shadow Brokers", description: "The Shadow Brokers released NSA-exploited vulnerabilities, including Eternal Blue and Double Pulsar.", color: "red" },
    { date: "April 25th, 2017", title: "Cisco NGFW | Meraki MX", description: "Talos released Snort™ signatures for Double Pulsar and SMB vulnerabilities.", color: "red" },
    { date: "May 12th, 2017 | 7:30 UTC", title: "Cisco Investigate", description: "WannaCry ransomware attack first reported by @MalwareTechBlog.", color: "red" },
    { date: "May 12th, 2017 | 7:43 UTC", title: "Cisco Umbrella", description: "Cisco Umbrella identified and blocked the kill switch domain globally.", color: "red" },
    { date: "May 12th, 2017 | 9:33 UTC", title: "Cisco AMP", description: "Cisco AMP detected and blocked WannaCry ransomware on multiple security platforms.", color: "red" },
    { date: "May 12th, 2017 | 10:12 UTC", title: "Cisco Umbrella", description: "Attack attributed to ransomware; kill switch domain categorized as malware.", color: "red" }
  ];

  return (
    <div className="main-container">
      <div className={`navbar-container ${showNavbar ? "visible" : "hidden"}`}>
        <Navbar />
      </div>

      <div className="timeline-container">
        <h1 className="timeline-title">Timeline of ‘WannaCry’ Ransomware Defense</h1>
        <div className="timeline">
          {events.map((event, index) => (
            <div key={index} className="timeline-event">
              <div className={`timeline-dot ${event.color}`}></div>
              <div className="timeline-content">
                <p className="timeline-date">{event.date}</p>
                <h2 className="timeline-event-title">{event.title}</h2>
                <p className="timeline-description">{event.description}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default Timeline;
