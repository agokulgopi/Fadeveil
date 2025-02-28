const axios = require("axios");

const testLogin = async () => {
  try {
    const response = await axios.post("http://localhost:5000/api/login", {
      email: "user@example.com", // Replace with an actual email in your database
      password: "1234"           // Replace with the correct password
    });

    console.log("✅ API Response:", response.data);
  } catch (error) {
    console.error("❌ Error:", error.response?.data || error.message);
  }
};

testLogin();

