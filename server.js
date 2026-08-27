const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const morgan = require("morgan");
const ExcelJS = require("exceljs");
const PDFDocument = require("pdfkit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
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
  role: { type: String, enum: ["user", "admin"], default: "user" },
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
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ message: "Admin only" });
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
      user: { id: user._id, name: user.name, email: user.email, role: user.role }
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

    // Hash password before saving
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
      "Private sector Engagement"
    ],
  },
  location: {
    type: String,
    enum: [
      "Regional Office",
      "Nairobi",
      "Nairobi Admin Stores",
      "Nairobi IT Stores",
      "RMU Stores",
      "Kisumu",
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
        { "returnInfo.returnedBy": { $regex: req.params.query, $options: "i" } }
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
    const colPurchaseDate = getCol(['Purchase Date', 'PurchaseDate', 'Date Purchased']) || 6;
    const colPurchasePrice = getCol(['Purchase Price', 'PurchasePrice', 'Price', 'Cost']) || 7;
    const colStatus = getCol(['Status']) || 8;
    const colDepartment = getCol(['Department', 'Dept']) || 9;
    const colLocation = getCol(['Location']) || 10;
    const colAssignedTo = getCol(['Assigned To', 'AssignedTo', 'Assignee', 'Staff Name', 'Owner']) || 11;
    const colCondition = getCol(['Condition']) || 12;

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
          purchaseDate: purchaseDate,
          purchasePrice: purchasePrice,
          status: row.getCell(colStatus).value?.toString().trim() || "Available",
          department: row.getCell(colDepartment).value?.toString().trim(),
          location: row.getCell(colLocation).value?.toString().trim(),
          assignedTo: row.getCell(colAssignedTo).value?.toString().trim(),
          condition: row.getCell(colCondition).value?.toString().trim() || "Good",
        };

        if (!assetData.assetTag || !assetData.category) {
          errorCount++;
          errors.push(`Row ${rowNumber}: Missing Asset Tag or Category`);
          return;
        }

        Object.keys(assetData).forEach(key => {
          if (assetData[key] === undefined || assetData[key] === null || assetData[key] === '') {
            delete assetData[key];
          }
        });

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

    asset.history.push({
      action: "Assigned",
      assignedTo: req.body.assignedTo,
      department: req.body.department,
      notes: req.body.notes || "Asset assigned",
    });

    await asset.save();
    res.json({ message: "Asset assigned", asset });

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
app.get("/api/export/excel", auth, async (req, res) => {
  try {
    const assets = await Asset.find();

    const workbook = new ExcelJS.Workbook();
    const sheet = workbook.addWorksheet("Assets Report");

    sheet.columns = [
      { header: "Asset Tag", key: "assetTag", width: 20 },
      { header: "Category", key: "category", width: 20 },
      { header: "Brand", key: "brand", width: 15 },
      { header: "Model", key: "model", width: 20 },
      { header: "Serial Number", key: "serialNumber", width: 25 },
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

    assets.forEach((a) =>
      sheet.addRow({
        assetTag: a.assetTag,
        category: a.category,
        brand: a.brand,
        model: a.model,
        serialNumber: a.serialNumber,
        purchaseDate: a.purchaseDate,
        purchasePrice: a.purchasePrice,
        status: a.status,
        department: a.department,
        location: a.location,
        assignedTo: a.assignedTo || "",
        returnedBy: a.returnInfo?.returnedBy || "",
        returnDate: a.returnInfo?.returnDate || "",
        condition: a.condition,
      })
    );

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

    const doc = new PDFDocument({ margin: 30 });

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", "attachment; filename=assets.pdf");

    doc.pipe(res);

    doc.fontSize(18).text("CARE IT ASSET REPORT", { align: "center" });
    doc.fontSize(10).text(`Generated: ${new Date().toLocaleDateString()}`, { align: "center" });
    doc.moveDown();

    assets.forEach((a, i) => {
      doc.fontSize(10).text(
        `${i + 1}. ${a.assetTag} | ${a.category} | ${a.status} | ${a.location}`
      );
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
