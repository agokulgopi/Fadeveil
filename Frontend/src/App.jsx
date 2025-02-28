import React from "react";
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import Login from "./Pages/Login";
import Register from "./Pages/Register";
import Home from "./Home";
import Home2 from "./Pages/Home2";
import FileUpload from "./Components/FileUpload";
import Workflow from "./Components/WorkFlow.jsx";
import Timeline from "./Components/Timeline";
import About from "./Pages/About";
import Contact from "./Pages/Contact";
import FileDownload from "./Pages/FileDownload.jsx";

// ✅ Private Route Component
const PrivateRoute = ({ element, allowedRoles }) => {
  const token = localStorage.getItem("token");
  const role = localStorage.getItem("role");

  if (!token) {
    return <Navigate to="/login" replace />; // Redirect if not authenticated
  }

  if (allowedRoles.includes(role)) {
    return element;
  } else {
    return <Navigate to="/login" replace />; // Redirect if role mismatch
  }
};

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        
        {/* ✅ Protected Routes Based on Role */}
        <Route path="/home" element={<PrivateRoute element={<Home />} allowedRoles={["Cyber Researcher"]} />} />
        <Route path="/home2" element={<PrivateRoute element={<Home2 />} allowedRoles={["Incident Responder"]} />} />

        <Route path="/upload" element={<FileUpload />} />
        <Route path="/workflow" element={<Workflow />} />
        <Route path="/timeline" element={<Timeline />} />
        <Route path="/filedownload" element={<FileDownload />} />
        <Route path="/about" element={<About />} />
        <Route path="/contact" element={<Contact />} />
      </Routes>
    </Router>
  );
}

export default App;
