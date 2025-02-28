import React, { useState } from "react";
import { Link } from "react-router-dom";
import axios from "axios"; // Import Axios
import video from "../Images/video.mp4";
import "../style.scss";

const Register = () => {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("Cyber Researcher"); // Default role
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    const userData = { name, email, password, role };
    console.log("📤 Sending Data to Backend:", userData);

    try {
      const response = await axios.post("http://localhost:5000/api/register", userData, {
        headers: {
          "Content-Type": "application/json",
        },
      });

      console.log("✅ Response from Backend:", response.data);
      setSuccess(response.data.message);

      // Reset form fields
      setName("");
      setEmail("");
      setPassword("");
      setRole("Cyber Researcher");
    } catch (err) {
      console.error("❌ Error Response:", err.response?.data || err.message);
      setError(err.response?.data?.message || "Something went wrong");
    }
  };

  return (
    <div className="formContainer">
      <video autoPlay loop muted playsInline>
        <source src={video} type="video/mp4" playsInline />
        Your browser does not support the video tag.
      </video>
      <div className="formWrapper">
        <span className="logo">FADEVEIL</span>
        <span className="title">Register</span>
        {error && <p className="error">{error}</p>}
        {success && <p className="success">{success}</p>}
        <form onSubmit={handleSubmit}>
          <input type="text" placeholder="Enter name" value={name} onChange={(e) => setName(e.target.value)} required />
          <input type="email" placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          <input type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} required />

          <select value={role} onChange={(e) => setRole(e.target.value)}>
          <option value="" disabled hidden>Select Role</option>
            <option value="Cyber Researcher">Cyber Researcher</option>
            <option value="Incident Responder">Incident Responder</option>
          </select>

          <button type="submit" disabled={!name || !email || !password || !role}>Sign up</button>
        </form>
        <p>
          Already have an account? <Link to="/login">Login</Link>
        </p>
      </div>
    </div>
  );
};

export default Register;
