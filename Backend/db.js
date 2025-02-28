require("dotenv").config(); // Load environment variables at the very beginning
const mongoose = require("mongoose");

const connectDB = async () => {
  try {
    if (!process.env.MONGO_URI) {
      throw new Error("❌ MONGO_URI is not defined in the .env file!");
    }

    console.log("🔍 Attempting to connect to MongoDB...");
    const conn = await mongoose.connect(process.env.MONGO_URI);
    console.log(`✅ MongoDB Connected: ${conn.connection.host}`);

    // Close the connection after success (only when running this file directly)
    if (require.main === module) {
      console.log("🔌 Closing MongoDB connection...");
      await mongoose.connection.close();
      console.log("✅ Connection closed.");
    }
  } catch (error) {
    console.error(`❌ MongoDB Connection Error: ${error.message}`);
    process.exit(1);
  }
};

module.exports = connectDB;

// Run the function if this file is executed directly (node db.js)
if (require.main === module) {
  console.log("🔍 MONGO_URI from .env:", process.env.MONGO_URI || "❌ Undefined");
  connectDB();
}
