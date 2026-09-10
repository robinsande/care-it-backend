const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const morgan = require("morgan");
const ExcelJS = require("exceljs");
const PDFDocument = require("pdfkit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const multer = require("multer");
const nodemailer = require("nodemailer");
require("dotenv").config();

const app = express();

/* =========================
   EMAIL CONFIGURATION
========================= */
const SMTP_USER = process.env.EMAIL_USER || "carepassreset@gmail.com";
const SMTP_PASS = (process.env.EMAIL_PASS || "spha swpq vsoo baju").replace(/\s+/g, "");
const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE || "gmail",
  auth: {
    user: SMTP_USER,
    pass: SMTP_PASS
  }
});

// Function to send verification code email
async function sendVerificationCodeEmail(email, code, userName) {
  try {
    const mailOptions = {
      from: `"CARE IT Asset Management" <${SMTP_USER}>`,
      to: email,
      subject: "CARE IT - Password Reset Verification Code",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background-color: #f3f4f6; padding: 20px; border-radius: 8px;">
            <h2 style="color: #1f2937; margin-top: 0;">CARE IT Asset Management</h2>
            <p style="color: #6b7280; font-size: 14px;">Password Reset Request</p>
          </div>

          <div style="padding: 30px; background-color: #ffffff;">
            <p>Hello ${userName},</p>
            
            <p>You requested to reset your password. Use the code below to proceed:</p>
            
            <div style="background-color: #f3f4f6; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0;">
              <h3 style="font-size: 36px; color: #3b82f6; letter-spacing: 10px; margin: 0;">
                ${code}
              </h3>
            </div>

            <p style="color: #6b7280; font-size: 14px;">
              <strong>This code will expire in 10 minutes.</strong>
            </p>

            <p style="color: #6b7280; font-size: 14px;">
              If you didn't request this password reset, please ignore this email or contact support.
            </p>

            <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 30px 0;">

            <p style="color: #9ca3af; font-size: 12px; margin-bottom: 0;">
              © 2025 CARE IT Asset Management. All rights reserved.
            </p>
          </div>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log(`✅ Verification code sent to ${email}`);
  } catch (error) {
    console.error("❌ Email sending error:", error);
    throw new Error("Failed to send verification email");
  }
}

/* =========================
   MIDDLEWARE
========================= */
// CORS
app.use(cors({
  origin: process.env.CORS_ORIGIN || "*",
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true
}));

// Body Parser
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));

// Logger
app.use(morgan(process.env.LOG_LEVEL || "dev"));

// File Upload
const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    if (file.mimetype === "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" ||
        file.mimetype === "application/vnd.ms-excel") {
      cb(null, true);
    } else {
      cb(new Error("Only Excel files are allowed"));
    }
  }
});

/* =========================
   DATABASE
========================= */
mongoose
  .connect(process.env.MONGODB_URL || "mongodb://127.0.0.1:27017/care_it_asset_management-app", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000,
  })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => {
    console.log("❌ DB Error:", err.message);
    process.exit(1);
  });

/* =========================
   USER MODEL
========================= */
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, unique: true, lowercase: true, trim: true, required: true },
  password: { type: String, required: true },
  mustChangePassword: { type: Boolean, default: false },
  role: { type: String, enum: ["user", "viewer", "admin", "superadmin"], default: "user" },
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

/* =========================
   PASSWORD RESET MODEL
========================= */
const passwordResetSchema = new mongoose.Schema({
  email: { type: String, required: true, lowercase: true },
  code: { type: String, required: true },
  verified: { type: Boolean, default: false },
  expiresAt: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now, expires: 600 } // Auto-delete after 10 minutes
});

const PasswordReset = mongoose.model("PasswordReset", passwordResetSchema);

/* =========================
   AUTH MIDDLEWARE
========================= */
const auth = (req, res, next) => {
  const header = req.headers.authorization;

  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ message: "No token provided" });
  }

  try {
    const token = header.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "secret123");
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
};

const adminOnly = (req, res, next) => {
  if (!req.user || !["admin", "superadmin"].includes(req.user.role)) {
    return res.status(403).json({ message: "Admin access required" });
  }
  next();
};

const superAdminOnly = (req, res, next) => {
  if (!req.user || req.user.role !== "superadmin") {
    return res.status(403).json({ message: "Super admin access required" });
  }
  next();
};

/* =========================
   AUTH ROUTES
========================= */

// REGISTER
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ message: "Name, email and password required" });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters" });
    }

    const exists = await User.findOne({ email: email.toLowerCase() });
    if (exists) {
      return res.status(400).json({ message: "Email already exists" });
    }

    // Hash password before saving
    const hashedPassword = await bcrypt.hash(password, parseInt(process.env.BCRYPT_ROUNDS || 10));

    const user = new User({ 
      name, 
      email: email.toLowerCase(), 
      password: hashedPassword,
      role: "user" 
    });
    
    await user.save();

    res.status(201).json({
      message: "User created successfully",
      user: { id: user._id, name: user.name, email: user.email, role: user.role }
    });

  } catch (err) {
    console.error("Register Error:", err);
    res.status(500).json({ message: err.message || "Registration failed" });
  }
});

// LOGIN
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ message: "Wrong password" });
    }

    const token = jwt.sign(
      { id: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET || "secret123",
      { expiresIn: process.env.JWT_EXPIRE || "7d" }
    );

    res.json({
      message: "Login successful",
      token,
      user: { id: user._id, name: user.name, email: user.email, role: user.role, mustChangePassword: user.mustChangePassword }
    });

  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ message: err.message || "Login failed" });
  }
});

// GET CURRENT USER
app.get("/api/auth/me", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// CREATE ADMIN
app.post("/api/auth/create-admin", auth, adminOnly, async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ message: "Name, email and password required" });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters" });
    }

    const exists = await User.findOne({ email: email.toLowerCase() });
    if (exists) {
      return res.status(400).json({ message: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, parseInt(process.env.BCRYPT_ROUNDS || 10));

    const user = new User({ 
      name, 
      email: email.toLowerCase(), 
      password: hashedPassword,
      role: "admin" 
    });
    
    await user.save();

    res.status(201).json({
      message: "Admin user created successfully",
      user: { id: user._id, name: user.name, email: user.email, role: user.role }
    });

  } catch (err) {
    console.error("Create Admin Error:", err);
    res.status(500).json({ message: err.message });
  }
});

// GET ALL USERS
app.get("/api/users", auth, adminOnly, async (req, res) => {
  try {
    const users = await User.find().select("-password").sort({ createdAt: -1 });
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// CREATE USER / VIEWER / ADMIN
app.post("/api/users", auth, adminOnly, async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: "Name, email and password are required" });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters" });
    }

    const allowedRoles = ["user", "viewer", "admin", "superadmin"];
    const selectedRole = allowedRoles.includes(role) ? role : "user";

    if (selectedRole === "superadmin" && req.user.role !== "superadmin") {
      return res.status(403).json({ message: "Only the super admin can create another super admin" });
    }

    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing) {
      return res.status(400).json({ message: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, parseInt(process.env.BCRYPT_ROUNDS || 10));
    const user = new User({
      name,
      email: email.toLowerCase(),
      password: hashedPassword,
      role: selectedRole,
    });

    await user.save();
    res.status(201).json({
      message: "User created successfully",
      user: { id: user._id, name: user.name, email: user.email, role: user.role }
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.put("/api/users/:id", auth, adminOnly, async (req, res) => {
  try {
    const { role } = req.body;
    const targetUser = await User.findById(req.params.id);

    if (!targetUser) {
      return res.status(404).json({ message: "User not found" });
    }

    if (targetUser.role === "superadmin" && req.user.role !== "superadmin") {
      return res.status(403).json({ message: "Only the super admin can edit a super admin" });
    }

    const allowedRoles = ["user", "viewer", "admin", "superadmin"];
    const selectedRole = allowedRoles.includes(role) ? role : targetUser.role;

    if (selectedRole === "superadmin" && req.user.role !== "superadmin") {
      return res.status(403).json({ message: "Only the super admin can assign the super admin role" });
    }

    targetUser.role = selectedRole;
    await targetUser.save();

    res.json({
      message: "User role updated successfully",
      user: { id: targetUser._id, name: targetUser.name, email: targetUser.email, role: targetUser.role }
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post("/api/users/:id/reset-password", auth, adminOnly, async (req, res) => {
  try {
    const targetUser = await User.findById(req.params.id);
    if (!targetUser) {
      return res.status(404).json({ message: "User not found" });
    }

    if (targetUser.role === "superadmin" && req.user.role !== "superadmin") {
      return res.status(403).json({ message: "Only the super admin can reset a super admin password" });
    }

    const temporaryPassword = crypto.randomBytes(9).toString("base64url").slice(0, 12);
    targetUser.password = await bcrypt.hash(temporaryPassword, parseInt(process.env.BCRYPT_ROUNDS || 10));
    targetUser.mustChangePassword = true;
    await targetUser.save();

    res.json({
      message: "Temporary password generated successfully",
      temporaryPassword,
      user: { id: targetUser._id, name: targetUser.name, email: targetUser.email }
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.delete("/api/users/:id", auth, adminOnly, async (req, res) => {
  try {
    const targetUser = await User.findById(req.params.id);
    if (!targetUser) {
      return res.status(404).json({ message: "User not found" });
    }

    if (targetUser.role === "superadmin" && req.user.role !== "superadmin") {
      return res.status(403).json({ message: "Only the super admin can delete a super admin" });
    }

    await targetUser.deleteOne();
    res.json({ message: "User deleted successfully" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// FORGOT PASSWORD - Send verification code
app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email required" });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    
    // Always return success for security (don't reveal if email exists)
    if (!user) {
      return res.json({ 
        message: "If an account exists with this email, a verification code will be sent",
        success: true 
      });
    }

    // Generate 6-digit code
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Delete any existing reset codes for this email
    await PasswordReset.deleteMany({ email: email.toLowerCase() });

    // Save new reset code
    await PasswordReset.create({
      email: email.toLowerCase(),
      code: code,
      expiresAt: expiresAt
    });

    // Send email with code
    await sendVerificationCodeEmail(email, code, user.name);

    res.json({ 
      message: "Verification code sent to your email",
      success: true 
    });

  } catch (err) {
    console.error("Forgot Password Error:", err);
    res.status(500).json({ message: err.message || "Error processing request" });
  }
});

// VERIFY CODE
app.post("/api/auth/verify-code", async (req, res) => {
  try {
    const { email, code } = req.body;

    if (!email || !code) {
      return res.status(400).json({ message: "Email and code required" });
    }

    const resetRecord = await PasswordReset.findOne({
      email: email.toLowerCase(),
      code: code,
      verified: false,
      expiresAt: { $gt: new Date() } // Not expired
    });

    if (!resetRecord) {
      return res.status(400).json({ message: "Invalid or expired verification code" });
    }

    // Mark as verified
    resetRecord.verified = true;
    await resetRecord.save();

    res.json({ 
      message: "Code verified successfully",
      verified: true 
    });

  } catch (err) {
    console.error("Verify Code Error:", err);
    res.status(500).json({ message: err.message || "Error verifying code" });
  }
});

// RESET PASSWORD
app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
      return res.status(400).json({ message: "Email and new password required" });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters" });
    }

    // Find verified reset record
    const resetRecord = await PasswordReset.findOne({
      email: email.toLowerCase(),
      verified: true,
      expiresAt: { $gt: new Date() } // Not expired
    });

    if (!resetRecord) {
      return res.status(400).json({ message: "Invalid reset request. Please verify your code first." });
    }

    // Find user
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Hash and update password
    const hashedPassword = await bcrypt.hash(newPassword, parseInt(process.env.BCRYPT_ROUNDS || 10));
    user.password = hashedPassword;
    user.mustChangePassword = false;
    await user.save();

    // Delete all reset records for this user
    await PasswordReset.deleteMany({ email: email.toLowerCase() });

    res.json({ 
      message: "Password reset successful",
      success: true 
    });

  } catch (err) {
    console.error("Reset Password Error:", err);
    res.status(500).json({ message: err.message || "Error resetting password" });
  }
});

app.post("/api/auth/change-password", auth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: "Current and new password are required" });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters" });
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const currentPasswordMatches = await bcrypt.compare(currentPassword, user.password);
    if (!currentPasswordMatches) {
      return res.status(400).json({ message: "Current password is incorrect" });
    }

    user.password = await bcrypt.hash(newPassword, parseInt(process.env.BCRYPT_ROUNDS || 10));
    user.mustChangePassword = false;
    await user.save();

    res.json({ message: "Password changed successfully", success: true });
  } catch (err) {
    res.status(500).json({ message: err.message || "Error changing password" });
  }
});

/* =========================
   ASSET MODEL
========================= */
const assetSchema = new mongoose.Schema({
  assetTag: { type: String, required: true, unique: true, uppercase: true },
  category: {
    type: String,
    enum: ["Laptops", "Mobile Phones", "Monitors","Projectors","TV","Printers", "Copiers", "Network Devices", "Tablets"],
    required: true,
  },
  brand: String,
  model: String,
  serialNumber: String,
  purchaseDate: Date,
  purchasePrice: Number,
  status: {
    type: String,
    enum: ["Available", "Assigned", "In Storage", "Under Repair", "Lost", "Aproved for disposal", "Disposed"],
    default: "Available",
  },
  assignedTo: String,
  assignedItems: [{ type: String }],
  assignmentDetails: String,
  assignmentItemDetails: { type: mongoose.Schema.Types.Mixed, default: {} },
  department: {
    type: String,
    enum: [
      "Operations",
      "Finance",
      "Administration & Logistics",
      "Procurement",
      "IT",
      "Communications",
      "Programs",
      "CASCADE",
      "Women Voices and Leadership (WVL)",
      "KRAPID+",
      "MOFA",
      "C2C",
      "Sowing Change",
      "SHE SOARS",
      "CSDW",
      "EXECUTIVE",
      "Security",
      "PQLA / MEAL– Program Quality Learning & Accountability",
      "Programs & Fund raising",
      "Risk and Compliance",
      "ESA",
      "Human Resource",
      "Private sector Engagement",
      "Project Driver"
    ],
  },
  location: {
    type: String,
    enum: [
      "Regional Office",
      "Nairobi",
      "Nairobi Admin Stores",
      "Nairobi IT Stores",
      "Nairobi Regional Stores",
      "RMU Stores",
      "Kisumu",
      "Migori",
      "Busia",
      "Nakuru",
      "Kajiado",
      "Garissa",
      "Dadaab",
      "Dadaab-DMO",
      "IFO",
      "Hagadera",
      "Dagahaley"
    ],
  },
  condition: {
    type: String,
    enum: ["New", "Good", "Faulty", "BER", "Damaged"],
    default: "Good",
  },
  generation: {
    type: String,
    enum: [
      "8th Gen", "9th Gen", "10th Gen", "11th Gen",
      "12th Gen", "13th Gen", "14th Gen", "15th Gen",
      "Latest"
    ],
    set: v => (v == null || v === "") ? undefined : v,
  },
  processor: {
    type: String,
    enum: [
      "Intel Core i3", "Intel Core i5", "Intel Core i7", "Intel Core i9",
      "Intel Core Ultra 5", "Intel Core Ultra 7", "Intel Core Ultra 9",
      "AMD Ryzen 3", "AMD Ryzen 5", "AMD Ryzen 7", "AMD Ryzen 9"
    ],
    set: v => (v == null || v === "") ? undefined : v,
  },
  ram: {
    type: String,
    enum: ["8GB", "16GB", "32GB", "64GB"],
    set: v => (v == null || v === "") ? undefined : v,
  },
  ssd: {
    type: String,
    enum: ["128GB", "256GB", "512GB", "1TB", "2TB", "4TB"],
    set: v => (v == null || v === "") ? undefined : v,
  },
  history: [
    {
      action: String,
      assignedTo: String,
      department: String,
      date: { type: Date, default: Date.now },
      notes: String,
    },
  ],
  checkout: {
    checkedOutBy: String,
    checkoutDate: Date,
    expectedReturnDate: Date,
  },
  returnInfo: {
    returnedBy: String,
    returnDate: Date,
    condition: String,
  },
}, { timestamps: true });

const Asset = mongoose.model("Asset", assetSchema);

const returnedAssetSchema = new mongoose.Schema({
  description: { type: String, required: true },
  category: { type: String, enum: ["Laptops", "Mobile Phones", "Monitors", "Projectors", "TV", "Printers", "Copiers", "Network Devices", "Tablets", "Accessories", "Other"], default: "Other" },
  brand: String,
  model: String,
  serialNumber: String,
  returnedBy: { type: String, required: true },
  receivedBy: String,
  department: String,
  location: String,
  condition: { type: String, enum: ["New", "Good", "Faulty", "BER", "Damaged"], default: "Good" },
  notes: String,
  returnDate: { type: Date, default: Date.now },
  status: { type: String, default: "Received" },
}, { timestamps: true });

const ReturnedAsset = mongoose.model("ReturnedAsset", returnedAssetSchema);

const borrowedItemSchema = new mongoose.Schema({
  itemName: { type: String, required: true },
  category: { type: String, enum: ["Laptop", "Charger", "Monitor", "Projector", "Printer", "Router", "Tablet", "Phone", "Accessory", "Other"], default: "Other" },
  description: String,
  serialNumber: String,
  assignedTo: { type: String, required: true },
  department: String,
  location: String,
  condition: { type: String, enum: ["New", "Good", "Faulty", "BER", "Damaged"], default: "Good" },
  issuedBy: String,
  issueDate: { type: Date, default: Date.now },
  returnDueDate: Date,
  notes: String,
  status: { type: String, enum: ["Issued", "Returned"], default: "Issued" },
}, { timestamps: true });

const BorrowedItem = mongoose.model("BorrowedItem", borrowedItemSchema);

/* =========================
   ASSET ROUTES
========================= */

// CREATE (Admin only)
app.post("/api/assets", auth, adminOnly, async (req, res) => {
  try {
    const asset = await Asset.create(req.body);
    res.status(201).json({ message: "Asset created", asset });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// GET ALL
app.get("/api/assets", auth, async (req, res) => {
  try {
    const assets = await Asset.find().sort({ createdAt: -1 });
    res.json(assets);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// GET SINGLE
app.get("/api/assets/:id", auth, async (req, res) => {
  try {
    const asset = await Asset.findById(req.params.id);
    if (!asset) return res.status(404).json({ message: "Asset not found" });
    res.json(asset);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// SEARCH
app.get("/api/assets/search/:query", auth, async (req, res) => {
  try {
    const assets = await Asset.find({
      $or: [
        { assetTag: { $regex: req.params.query, $options: "i" } },
        { serialNumber: { $regex: req.params.query, $options: "i" } },
        { model: { $regex: req.params.query, $options: "i" } },
        { assignedTo: { $regex: req.params.query, $options: "i" } },
        { "returnInfo.returnedBy": { $regex: req.params.query, $options: "i" } },
        { generation: { $regex: req.params.query, $options: "i" } },
        { processor: { $regex: req.params.query, $options: "i" } },
        { ram: { $regex: req.params.query, $options: "i" } },
        { ssd: { $regex: req.params.query, $options: "i" } },
        { brand: { $regex: req.params.query, $options: "i" } }
      ]
    }).sort({ createdAt: -1 });
    res.json(assets);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// UPDATE (Admin only)
app.put("/api/assets/:id", auth, adminOnly, async (req, res) => {
  try {
    const asset = await Asset.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true });
    if (!asset) return res.status(404).json({ message: "Asset not found" });
    res.json({ message: "Asset updated", asset });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// DELETE (Admin only)
app.delete("/api/assets/:id", auth, adminOnly, async (req, res) => {
  try {
    const asset = await Asset.findByIdAndDelete(req.params.id);
    if (!asset) return res.status(404).json({ message: "Asset not found" });
    res.json({ message: "Asset deleted", asset });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* =========================
   IMPORT EXCEL
========================= */
app.post("/api/import/excel", auth, adminOnly, upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: "No file uploaded" });
    }

    const workbook = new ExcelJS.Workbook();
    await workbook.xlsx.load(req.file.buffer);

    const worksheet = workbook.worksheets[0];
    const assets = [];
    let importedCount = 0;
    let errorCount = 0;
    const errors = [];

    const headerRow = worksheet.getRow(1);
    const colMap = {};
    headerRow.eachCell({ includeEmpty: true }, (cell, colNumber) => {
      const header = cell.value?.toString().trim().toLowerCase().replace(/\s+/g, ' ') || '';
      colMap[header] = colNumber;
    });

    const getCol = (names) => {
      for (const name of names) {
        const key = name.toLowerCase().trim().replace(/\s+/g, ' ');
        if (colMap[key]) return colMap[key];
      }
      return null;
    };

    const colAssetTag = getCol(['Asset Tag', 'AssetTag', 'Tag']) || 1;
    const colCategory = getCol(['Category']) || 2;
    const colBrand = getCol(['Brand']) || 3;
    const colModel = getCol(['Model']) || 4;
    const colSerial = getCol(['Serial Number', 'SerialNumber', 'Serial No', 'SN']) || 5;
    const colGeneration = getCol(['Generation', 'Gen', 'CPU Gen', 'Processor Gen']) || 6;
    const colProcessor = getCol(['Processor', 'CPU', 'Cpu', 'Chip']) || 7;
    const colRAM = getCol(['RAM', 'Memory', 'Ram Memory']) || 8;
    const colSSD = getCol(['SSD', 'Storage', 'Disk', 'Hard Disk', 'HDD', 'Ssd']) || 9;
    const colPurchaseDate = getCol(['Purchase Date', 'PurchaseDate', 'Date Purchased']) || 10;
    const colPurchasePrice = getCol(['Purchase Price', 'PurchasePrice', 'Price', 'Cost']) || 11;
    const colStatus = getCol(['Status']) || 12;
    const colDepartment = getCol(['Department', 'Dept']) || 13;
    const colLocation = getCol(['Location']) || 14;
    const colAssignedTo = getCol(['Assigned To', 'AssignedTo', 'Assignee', 'Staff Name', 'Owner']) || 15;
    const colReturnedBy = getCol(['Returned By', 'ReturnedBy', 'Returner', 'Returned By Name']) || 16;
    const colReturnDate = getCol(['Return Date', 'ReturnDate', 'Date Returned', 'Returned Date']) || 17;
    const colCondition = getCol(['Condition']) || 18;

    worksheet.eachRow((row, rowNumber) => {
      if (rowNumber === 1) return;

      try {
        const rawDate = row.getCell(colPurchaseDate).value;
        let purchaseDate = rawDate;
        if (rawDate instanceof Date) {
          purchaseDate = rawDate;
        } else if (typeof rawDate === 'string' && rawDate.trim()) {
          const d = new Date(rawDate);
          if (!isNaN(d.getTime())) purchaseDate = d;
        } else if (typeof rawDate === 'number') {
          const excelEpoch = new Date(Date.UTC(1899, 11, 30));
          purchaseDate = new Date(excelEpoch.getTime() + rawDate * 86400000);
        }

        const rawReturnDate = row.getCell(colReturnDate).value;
        let returnDate = null;
        if (rawReturnDate instanceof Date) {
          returnDate = rawReturnDate;
        } else if (typeof rawReturnDate === 'string' && rawReturnDate.trim()) {
          const rd = new Date(rawReturnDate);
          if (!isNaN(rd.getTime())) returnDate = rd;
        } else if (typeof rawReturnDate === 'number') {
          const excelEpoch = new Date(Date.UTC(1899, 11, 30));
          returnDate = new Date(excelEpoch.getTime() + rawReturnDate * 86400000);
        }

        let purchasePrice = row.getCell(colPurchasePrice).value;
        if (purchasePrice && typeof purchasePrice === 'object' && purchasePrice.result !== undefined) {
          purchasePrice = purchasePrice.result;
        }

        const assetData = {
          assetTag: row.getCell(colAssetTag).value?.toString().toUpperCase().trim(),
          category: row.getCell(colCategory).value?.toString().trim(),
          brand: row.getCell(colBrand).value?.toString().trim(),
          model: row.getCell(colModel).value?.toString().trim(),
          serialNumber: row.getCell(colSerial).value?.toString().trim(),
          generation: row.getCell(colGeneration).value?.toString().trim(),
          processor: row.getCell(colProcessor).value?.toString().trim(),
          ram: row.getCell(colRAM).value?.toString().trim(),
          ssd: row.getCell(colSSD).value?.toString().trim(),
          purchaseDate: purchaseDate,
          purchasePrice: purchasePrice,
          status: row.getCell(colStatus).value?.toString().trim() || "Available",
          department: row.getCell(colDepartment).value?.toString().trim(),
          location: row.getCell(colLocation).value?.toString().trim(),
          assignedTo: row.getCell(colAssignedTo).value?.toString().trim(),
          condition: row.getCell(colCondition).value?.toString().trim() || "Good",
        };

        const returnedByVal = row.getCell(colReturnedBy).value?.toString().trim();
        if (returnedByVal || returnDate) {
          assetData.returnInfo = {
            returnedBy: returnedByVal || "",
            returnDate: returnDate || undefined,
          };
        }

        if (!assetData.assetTag || !assetData.category) {
          errorCount++;
          errors.push(`Row ${rowNumber}: Missing Asset Tag or Category`);
          return;
        }

        Object.keys(assetData).forEach(key => {
          if (assetData[key] === undefined || assetData[key] === null || assetData[key] === '') {
            if (key === 'returnInfo') return;
            delete assetData[key];
          }
        });
        if (assetData.returnInfo) {
          const ri = assetData.returnInfo;
          if ((!ri.returnedBy || ri.returnedBy === '') && !ri.returnDate) {
            delete assetData.returnInfo;
          }
        }

        assets.push(assetData);
      } catch (err) {
        errorCount++;
        errors.push(`Row ${rowNumber}: ${err.message}`);
      }
    });

    console.log(`Parsed ${assets.length} valid assets from Excel`);

    // Insert assets into database
    if (assets.length > 0) {
      try {
        const result = await Asset.insertMany(assets, { ordered: false });
        importedCount = result.length;
        console.log(`Successfully inserted ${importedCount} assets`);
      } catch (err) {
        // Handle duplicate key errors
        if (err.code === 11000) {
          importedCount = err.insertedCount || 0;
          const duplicateCount = assets.length - importedCount;
          errors.push(`${duplicateCount} assets had duplicate Asset Tags`);
          errorCount += duplicateCount;
          console.log(`Inserted ${importedCount} assets, ${duplicateCount} duplicates skipped`);
        } else {
          console.error("Insert error:", err);
          throw err;
        }
      }
    }

    res.json({
      message: "Import completed",
      importedCount,
      errorCount,
      errors: errors.length > 0 ? errors : undefined,
      totalProcessed: importedCount + errorCount
    });

  } catch (err) {
    console.error("Import Error:", err);
    res.status(500).json({ message: err.message || "Import failed" });
  }
});

/* =========================
   ASSIGN ASSET
========================= */
app.put("/api/assets/:id/assign", auth, async (req, res) => {
  try {
    const asset = await Asset.findById(req.params.id);
    if (!asset) return res.status(404).json({ message: "Asset not found" });

    asset.assignedTo = req.body.assignedTo;
    asset.department = req.body.department;
    asset.status = "Assigned";

    if (Array.isArray(req.body.assignedItems) && req.body.assignedItems.length) {
      asset.assignedItems = req.body.assignedItems;
    } else if (req.body.assignedItems === undefined) {
      asset.assignedItems = asset.assignedItems || [];
    } else {
      asset.assignedItems = [];
    }

    asset.assignmentDetails = req.body.assignmentDetails || req.body.description || req.body.notes || asset.assignmentDetails || "";
    if (req.body.assignmentItemDetails !== undefined) {
      asset.assignmentItemDetails = req.body.assignmentItemDetails;
    }

    const assignmentNote = asset.assignmentDetails || `Assigned to ${req.body.assignedTo || "staff"}`;
    asset.history.push({
      action: "Assigned",
      assignedTo: req.body.assignedTo,
      department: req.body.department,
      notes: assignmentNote,
    });

    await asset.save();
    res.json({ message: "Asset assigned", asset });

  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post("/api/assets/bulk-assign", auth, adminOnly, async (req, res) => {
  try {
    const { assetIds = [], assignedTo, department, description, notes } = req.body || {};

    if (!assignedTo || !Array.isArray(assetIds) || assetIds.length === 0) {
      return res.status(400).json({ message: "Assigned staff and at least one asset are required" });
    }

    const updatedAssets = [];
    const assignmentNote = description || notes || `Assigned to ${assignedTo}`;

    for (const assetId of assetIds) {
      const asset = await Asset.findById(assetId);
      if (!asset) continue;

      asset.assignedTo = assignedTo;
      asset.department = department || asset.department;
      asset.status = "Assigned";
      if (Array.isArray(req.body.assignedItems) && req.body.assignedItems.length) {
        asset.assignedItems = req.body.assignedItems;
      } else {
        asset.assignedItems = asset.assignedItems || [];
      }
      asset.assignmentDetails = description || notes || asset.assignmentDetails || "";
      if (req.body.assignmentItemDetails !== undefined) {
        asset.assignmentItemDetails = req.body.assignmentItemDetails;
      }
      asset.history.push({
        action: "Assigned",
        assignedTo,
        department: department || asset.department,
        notes: assignmentNote,
        date: new Date(),
      });

      await asset.save();
      updatedAssets.push(asset);
    }

    res.json({ message: `${updatedAssets.length} asset(s) assigned successfully`, assets: updatedAssets });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* =========================
   RETURN ASSET
========================= */
app.put("/api/assets/:id/return", auth, async (req, res) => {
  try {
    const asset = await Asset.findById(req.params.id);
    if (!asset) return res.status(404).json({ message: "Asset not found" });

    asset.status = "Available";
    asset.assignedTo = null;

    asset.returnInfo = {
      returnedBy: req.body.returnedBy,
      returnDate: new Date(),
      condition: req.body.condition || asset.condition,
    };

    asset.history.push({
      action: "Returned",
      assignedTo: req.body.returnedBy,
      notes: req.body.notes || `Asset returned by ${req.body.returnedBy || "unknown"}`,
      date: new Date(),
    });

    await asset.save();
    res.json({ message: "Asset returned", asset });

  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// UNREGISTERED RETURNED ASSET RECORD
app.post("/api/returned-assets", auth, adminOnly, async (req, res) => {
  try {
    const payload = req.body || {};
    const entry = await ReturnedAsset.create({
      description: payload.description || payload.itemName || "Returned item",
      category: payload.category || "Other",
      brand: payload.brand || "",
      model: payload.model || "",
      serialNumber: payload.serialNumber || "",
      returnedBy: payload.returnedBy || "",
      receivedBy: payload.receivedBy || req.user?.email || "",
      department: payload.department || "",
      location: payload.location || "",
      condition: payload.condition || "Good",
      notes: payload.notes || "",
      returnDate: payload.returnDate ? new Date(payload.returnDate) : new Date(),
      status: payload.status || "Received",
    });

    res.status(201).json({ message: "Returned asset recorded", entry });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/api/returned-assets", auth, adminOnly, async (req, res) => {
  try {
    const items = await ReturnedAsset.find().sort({ createdAt: -1 });
    res.json(items);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// IT ISSUE / BORROW RECORD
app.post("/api/it-issues", auth, adminOnly, async (req, res) => {
  try {
    const payload = req.body || {};
    const issue = await BorrowedItem.create({
      itemName: payload.itemName || "IT item",
      category: payload.category || "Other",
      description: payload.description || "",
      serialNumber: payload.serialNumber || "",
      assignedTo: payload.assignedTo || "",
      department: payload.department || "",
      location: payload.location || "",
      condition: payload.condition || "Good",
      issuedBy: payload.issuedBy || req.user?.email || "",
      issueDate: payload.issueDate ? new Date(payload.issueDate) : new Date(),
      returnDueDate: payload.returnDueDate ? new Date(payload.returnDueDate) : null,
      notes: payload.notes || "",
      status: payload.status || "Issued",
    });

    res.status(201).json({ message: "IT item issued", issue });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/api/it-issues", auth, adminOnly, async (req, res) => {
  try {
    const issues = await BorrowedItem.find().sort({ createdAt: -1 });
    res.json(issues);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* =========================
   DASHBOARD
========================= */
app.get("/api/dashboard/status", auth, async (req, res) => {
  try {
    const byStatus = await Asset.aggregate([
      { $group: { _id: "$status", count: { $sum: 1 } } }
    ]);
    const map = Object.fromEntries(byStatus.map(s => [s._id, s.count]));
    const damagedFaulty = await Asset.countDocuments({
      condition: { $in: ["Faulty", "Damaged"] },
      status: { $ne: "Under Repair" }
    });
    res.json([
      { _id: "Available (Ready for Issuing)", status: "Available", count: map["Available"] || 0 },
      { _id: "In Storage (Good working condition)", status: "In Storage", count: map["In Storage"] || 0 },
      { _id: "Assigned (Assigned to Staff)", status: "Assigned", count: map["Assigned"] || 0 },
      { _id: "Under Repair (Faulty - Can be Fixed)", status: "Under Repair", count: map["Under Repair"] || 0 },
      { _id: "Faulty (Can be Fixed)", status: "Faulty", count: damagedFaulty || 0 },
      { _id: "Lost", status: "Lost", count: map["Lost"] || 0 }
    ]);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/api/dashboard/location", auth, async (req, res) => {
  try {
    const stats = await Asset.aggregate([
      { $group: { _id: "$location", count: { $sum: 1 } } }
    ]);
    res.json(stats);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/api/dashboard/department", auth, async (req, res) => {
  try {
    const stats = await Asset.aggregate([
      { $group: { _id: "$department", count: { $sum: 1 } } }
    ]);
    res.json(stats);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/api/dashboard/category", auth, async (req, res) => {
  try {
    const stats = await Asset.aggregate([
      { $group: { _id: "$category", count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    res.json(stats);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/api/dashboard/category/faulty", auth, async (req, res) => {
  try {
    const stats = await Asset.aggregate([
      { $match: { condition: { $in: ["Faulty", "Damaged"] } } },
      { $group: { _id: "$category", count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    res.json(stats);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/api/dashboard/category/new", auth, async (req, res) => {
  try {
    const stats = await Asset.aggregate([
      { $match: { condition: "New" } },
      { $group: { _id: "$category", count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    res.json(stats);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/api/dashboard/category/good", auth, async (req, res) => {
  try {
    const stats = await Asset.aggregate([
      { $match: { condition: { $in: ["Good", "New"] } } },
      { $group: { _id: "$category", count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    res.json(stats);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/api/dashboard/category/lost", auth, async (req, res) => {
  try {
    const stats = await Asset.aggregate([
      { $match: { status: "Lost" } },
      { $group: { _id: "$category", count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    res.json(stats);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ---- Availability (status=Available OR status=In Storage) breakdown per dimension ---- */
function availableMatch() {
  return { $match: { status: { $in: ["Available", "In Storage"] } } };
}

app.get("/api/dashboard/available/category", auth, async (req, res) => {
  try {
    const stats = await Asset.aggregate([
      availableMatch(),
      { $group: { _id: "$category", count: { $sum: 1 } } }
    ]);
    res.json(Object.fromEntries(stats.map(s => [s._id, s.count])));
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/api/dashboard/available/department", auth, async (req, res) => {
  try {
    const stats = await Asset.aggregate([
      availableMatch(),
      { $group: { _id: "$department", count: { $sum: 1 } } }
    ]);
    res.json(Object.fromEntries(stats.map(s => [s._id, s.count])));
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/api/dashboard/available/location", auth, async (req, res) => {
  try {
    const stats = await Asset.aggregate([
      availableMatch(),
      { $group: { _id: "$location", count: { $sum: 1 } } }
    ]);
    res.json(Object.fromEntries(stats.map(s => [s._id, s.count])));
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/api/dashboard/available/status", auth, async (req, res) => {
  try {
    const stats = await Asset.aggregate([
      availableMatch(),
      { $group: { _id: "$status", count: { $sum: 1 } } }
    ]);
    res.json(Object.fromEntries(stats.map(s => [s._id, s.count])));
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/api/dashboard/available/condition", auth, async (req, res) => {
  try {
    const stats = await Asset.aggregate([
      availableMatch(),
      { $group: { _id: "$condition", count: { $sum: 1 } } }
    ]);
    res.json(Object.fromEntries(stats.map(s => [s._id, s.count])));
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/api/dashboard/available/total", auth, async (req, res) => {
  try {
    const total = await Asset.countDocuments();
    const available = await Asset.countDocuments({ status: "Available" });
    const storage = await Asset.countDocuments({ status: "In Storage" });
    const issuedReady = available + storage;
    res.json({
      total,
      available,
      inStorage: storage,
      issuable: issuedReady,
      assigned: await Asset.countDocuments({ status: "Assigned" }),
      underRepair: await Asset.countDocuments({ status: "Under Repair" }),
      lost: await Asset.countDocuments({ status: "Lost" })
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* =========================
   EXPORT EXCEL
========================= */
const ASSET_EXPORT_COLUMNS = [
  { header: "Asset Tag", key: "assetTag", width: 20 },
  { header: "Category", key: "category", width: 20 },
  { header: "Brand", key: "brand", width: 15 },
  { header: "Model", key: "model", width: 20 },
  { header: "Serial Number", key: "serialNumber", width: 25 },
  { header: "Generation", key: "generation", width: 14 },
  { header: "Processor", key: "processor", width: 22 },
  { header: "RAM", key: "ram", width: 10 },
  { header: "SSD", key: "ssd", width: 10 },
  { header: "Purchase Date", key: "purchaseDate", width: 15 },
  { header: "Purchase Price", key: "purchasePrice", width: 15 },
  { header: "Status", key: "status", width: 15 },
  { header: "Department", key: "department", width: 25 },
  { header: "Location", key: "location", width: 25 },
  { header: "Assigned To", key: "assignedTo", width: 28 },
  { header: "Returned By", key: "returnedBy", width: 28 },
  { header: "Return Date", key: "returnDate", width: 15 },
  { header: "Condition", key: "condition", width: 15 },
];

function getAssetExportRow(asset) {
  return {
    assetTag: asset.assetTag,
    category: asset.category,
    brand: asset.brand,
    model: asset.model,
    serialNumber: asset.serialNumber,
    generation: asset.generation || "",
    processor: asset.processor || "",
    ram: asset.ram || "",
    ssd: asset.ssd || "",
    purchaseDate: asset.purchaseDate,
    purchasePrice: asset.purchasePrice,
    status: asset.status,
    department: asset.department,
    location: asset.location,
    assignedTo: asset.assignedTo || "",
    returnedBy: asset.returnInfo?.returnedBy || "",
    returnDate: asset.returnInfo?.returnDate || "",
    condition: asset.condition,
  };
}

app.get("/api/export/excel", auth, async (req, res) => {
  try {
    const assets = await Asset.find();

    const workbook = new ExcelJS.Workbook();
    const sheet = workbook.addWorksheet("Assets Report");

    sheet.columns = ASSET_EXPORT_COLUMNS;

    assets.forEach((asset) => sheet.addRow(getAssetExportRow(asset)));

    const headerRow = sheet.getRow(1);
    headerRow.font = { bold: true, color: { argb: "FFFFFFFF" }, name: "Times New Roman" };
    headerRow.fill = {
      type: "pattern",
      pattern: "solid",
      fgColor: { argb: "FF2F5496" },
    };
    headerRow.height = 28;
    headerRow.alignment = { vertical: "middle" };

    sheet.eachRow({ includeEmpty: false }, (row, rowNumber) => {
      row.font = { name: "Times New Roman" };
      if (rowNumber > 1) {
        row.alignment = { vertical: "middle" };
        if (rowNumber % 2 === 0) {
          row.fill = {
            type: "pattern",
            pattern: "solid",
            fgColor: { argb: "FFD6E4F0" },
          };
        } else {
          row.fill = {
            type: "pattern",
            pattern: "solid",
            fgColor: { argb: "FFB8CCE4" },
          };
        }
      }
    });

    sheet.eachRow((row) => {
      row.eachCell({ includeEmpty: true }, (cell) => {
        cell.border = {
          top: { style: "thin", color: { argb: "FF95B3D7" } },
          left: { style: "thin", color: { argb: "FF95B3D7" } },
          bottom: { style: "thin", color: { argb: "FF95B3D7" } },
          right: { style: "thin", color: { argb: "FF95B3D7" } },
        };
      });
    });

    sheet.autoFilter = {
      from: { row: 1, column: 1 },
      to: { row: 1, column: sheet.columns.length },
    };

    res.setHeader(
      "Content-Type",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    );
    res.setHeader("Content-Disposition", "attachment; filename=assets.xlsx");

    await workbook.xlsx.write(res);
    res.end();
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* =========================
   EXPORT PDF
========================= */
app.get("/api/export/pdf", auth, async (req, res) => {
  try {
    const assets = await Asset.find();

    const doc = new PDFDocument({
      layout: "landscape",
      size: "LEGAL",
      margins: { top: 28, bottom: 28, left: 24, right: 24 },
      bufferPages: true,
    });

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", "attachment; filename=assets.pdf");

    doc.pipe(res);

    const pageWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
    const pageBottom = doc.page.height - doc.page.margins.bottom;
    const totalColumnWidth = ASSET_EXPORT_COLUMNS.reduce((sum, column) => sum + column.width, 0);
    const columnWidths = ASSET_EXPORT_COLUMNS.map((column) => pageWidth * column.width / totalColumnWidth);
    const rowData = assets.map(getAssetExportRow);
    const headerHeight = 24;
    const fontSize = 6.5;

    const formatPdfValue = (value, key) => {
      if (value == null || value === "") return "";
      if (key === "purchaseDate" || key === "returnDate") return new Date(value).toLocaleDateString();
      if (key === "purchasePrice") return Number(value).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
      return String(value);
    };

    const drawTableHeader = () => {
      let x = doc.page.margins.left;
      doc.font("Times-Bold").fontSize(fontSize).fillColor("#FFFFFF");
      ASSET_EXPORT_COLUMNS.forEach((column, index) => {
        const width = columnWidths[index];
        doc.save().rect(x, doc.y, width, headerHeight).fill("#2F5496").restore();
        doc.fillColor("#FFFFFF").text(column.header, x + 3, doc.y + 7, {
          width: width - 6,
          height: headerHeight - 6,
          ellipsis: true,
          lineBreak: false,
        });
        doc.rect(x, doc.y - headerHeight, width, headerHeight).stroke("#95B3D7");
        x += width;
      });
      doc.y += headerHeight;
    };

    doc.font("Times-Bold").fontSize(16).fillColor("#1F2937").text("CARE IT ASSET REPORT", { align: "center" });
    doc.font("Times-Roman").fontSize(9).fillColor("#4B5563").text(`Generated: ${new Date().toLocaleDateString()}`, { align: "center" });
    doc.moveDown(0.8);
    drawTableHeader();

    rowData.forEach((row, rowIndex) => {
      if (doc.y + 24 > pageBottom) {
        doc.addPage();
        drawTableHeader();
      }

      const rowTop = doc.y;
      const cellHeights = ASSET_EXPORT_COLUMNS.map((column, index) => doc.heightOfString(formatPdfValue(row[column.key], column.key), {
        width: columnWidths[index] - 6,
        lineGap: 0,
      }));
      const rowHeight = Math.max(20, Math.min(52, Math.max(...cellHeights) + 7));
      let x = doc.page.margins.left;

      ASSET_EXPORT_COLUMNS.forEach((column, columnIndex) => {
        const width = columnWidths[columnIndex];
        const fill = rowIndex % 2 === 0 ? "#D6E4F0" : "#B8CCE4";
        doc.save().rect(x, rowTop, width, rowHeight).fill(fill).restore();
        doc.font("Times-Roman").fontSize(fontSize).fillColor("#1F2937").text(
          formatPdfValue(row[column.key], column.key),
          x + 3,
          rowTop + 3,
          { width: width - 6, height: rowHeight - 6, ellipsis: true, lineGap: 0 }
        );
        doc.rect(x, rowTop, width, rowHeight).stroke("#95B3D7");
        x += width;
      });
      doc.y = rowTop + rowHeight;
    });

    doc.end();
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* =========================
   HEALTH CHECK
========================= */
app.get("/health", (req, res) => {
  res.json({ status: "OK", timestamp: new Date().toISOString() });
});

/* =========================
   ERROR HANDLING
========================= */
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: "Internal Server Error", error: err.message });
});

/* =========================
   START SERVER
========================= */
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});

module.exports = app;
