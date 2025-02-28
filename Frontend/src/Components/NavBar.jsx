import React, { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import "./Navbar.css";
import img from "../Images/fadeveilbg.png";

const Navbar = () => {
  const navigate = useNavigate();
  const [role, setRole] = useState("");

  useEffect(() => {
    const savedRole = localStorage.getItem("role");
    if (savedRole) {
      setRole(savedRole);
    }
  }, []);

  const handleLogout = () => {
    localStorage.clear();
    navigate("/login");
  };

  // Determine the correct home path
  const homePath = role === "Cyber Researcher" ? "/home" : role === "Incident Responder" ? "/home2" : "/login";

  return (
    <nav className="navbar">
      <div className="logo">
        <img src={img} alt="FadeVeil Logo" className="logo-img" />
      </div>
      <ul className="nav-links">
        <li><Link to={homePath}>HOME</Link></li>
        <li><Link to="/timeline">BROWSE TOPICS</Link></li>
        <li><Link to="/workflow">HOW IT WORKS</Link></li>
        {role === "Cyber Researcher" && <li><Link to="/filedownload">Decrypted files</Link></li>}
        <li><Link to="/contact">CONTACT</Link></li>
        <li><Link to="/about">ABOUT</Link></li>
        <li className="role-display" style={{ marginLeft: "40px" }}>
          <strong style={{ display: "inline" }}>Role:</strong> {role || "Not Assigned"}
        </li>
        <li><button className="logout-btn" onClick={handleLogout}>LOGOUT</button></li>
      </ul>
    </nav>
  );
};

export default Navbar;
