import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import axios from "axios";
import "../Style.scss";
import video from "../Images/video.mp4";

const Login = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    try {
      const response = await axios.post("http://localhost:5000/api/login", { email, password }, {
        headers: { "Content-Type": "application/json" }
      });

      setSuccess(response.data.message);
      localStorage.setItem("token", response.data.token);
      localStorage.setItem("role", response.data.role); // ✅ Store role

      // ✅ Redirect based on role
      if (response.data.role === "Cyber Researcher") {
        navigate("/home");
      } else if (response.data.role === "Incident Responder") {
        navigate("/home2");
      } else {
        navigate("/home2");
      }

    } catch (err) {
      console.error("Login Error:", err.response || err);
      setError(err.response?.data?.message || "❌ Login failed. Try again.");
    }
  };

  return (
    <div className="formContainer">
      <video autoPlay loop muted playsInline>
        <source src={video} type="video/mp4" />
      </video>
      <div className="formWrapper">
        <span className="logo">FADEVEIL</span>
        <span className="title">Login</span>
        <form onSubmit={handleSubmit}>
          <input type="email" placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          <input type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} required />
          <button type="submit" disabled={!email || !password}>Sign in</button>
        </form>
        {success && <p style={{ color: "green" }}>{success}</p>}
        {error && <p style={{ color: "red" }}>{error}</p>}
        <p>You don't have an account? <Link to="/register">Register</Link></p>
      </div>
    </div>
  );
};

export default Login;
