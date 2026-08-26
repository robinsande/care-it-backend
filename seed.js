const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
require("dotenv").config();

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URL || "mongodb://127.0.0.1:27017/care_it_asset_management-app")
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.log("❌ DB Error:", err));

// User Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, enum: ["user", "admin"], default: "user" },
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

// Seed function
async function seedAdmin() {
  try {
    // Check if admin exists
    const adminExists = await User.findOne({ email: "admin@care.com" });
    
    if (adminExists) {
      console.log("✅ Admin already exists");
      process.exit(0);
    }

    // Create admin user
    const hashedPassword = await bcrypt.hash("admin123", 10);
    
    const admin = new User({
      name: "Admin User",
      email: "admin@care.com",
      password: hashedPassword,
      role: "admin"
    });

    await admin.save();
    console.log("✅ Admin user created successfully!");
    console.log("📧 Email: admin@care.com");
    console.log("🔐 Password: admin123");
    
    process.exit(0);
  } catch (err) {
    console.log("❌ Error:", err.message);
    process.exit(1);
  }
}

seedAdmin();