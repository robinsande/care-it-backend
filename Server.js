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
const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE || "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Function to send verification code email
async function sendVerificationCodeEmail(email, code, userName) {
  try {
    const mailOptions = {
      from: process.env.EMAIL_USER,
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
  origin: "*",
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

// Body Parser
app.use(express.json());

// Logger
app.use(morgan("dev"));

// File Upload
const upload = multer({ 
  storage: multer.memoryStorage(),
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
  .connect(process.env.MONGODB_URL || "mongodb://127.0.0.1:27017/care_it_asset_management-app")
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.log("❌ DB Error:", err));

/* =========================
   USER MODEL
========================= */
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true, lowercase: true, trim: true },
  password: String,
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

    const exists = await User.findOne({ email: email.toLowerCase() });
    if (exists) {
      return res.status(400).json({ message: "Email already exists" });
    }

    // Hash password before saving
    const hashedPassword = await bcrypt.hash(password, 10);

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
      { expiresIn: "7d" }
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

    const exists = await User.findOne({ email: email.toLowerCase() });
    if (exists) {
      return res.status(400).json({ message: "Email already exists" });
    }

    // Hash password before saving
    const hashedPassword = await bcrypt.hash(password, 10);

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
    const hashedPassword = await bcrypt.hash(newPassword, 10);
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
    enum: ["Laptops", "Mobile Phones", "Monitors","Projectors","TV","Printers", "Copiers", "Network Devices"],
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
      "Executive Director","Administration","Human Resource","Finance",
      "Procurement","Operations","IT"
    ],
  },
  location: {
    type: String,
    enum: [
      "Dadaab - DMO","Dadaab - IFO","Dadaab - Hagadera","Dadaab - Dagahaley",
      "Dadaab - DMO Stores","Dadaab - IFO Stores","Dadaab - Hagadera Stores","Dadaab - Dagahaley Stores",
      "Nairobi","Nairobi Admin Office","Nairobi Admin Stores","Nairobi RMU Office","Nairobi RMU Stores",
      "Nairobi HR Office","Nairobi Finance Office","Nairobi Procurement Office","Nairobi IT Office","Nairobi IT Stores",
      "Kisumu Office","Kisumu Stores","Garissa Office","Garissa Stores",
      "Nakuru Office","Nakuru Stores","Mandera Office","Mandera Stores"
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
    const assets = await Asset.find();
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
        { assignedTo: { $regex: req.params.query, $options: "i" } }
      ]
    });
    res.json(assets);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// UPDATE (Admin only)
app.put("/api/assets/:id", auth, adminOnly, async (req, res) => {
  try {
    const asset = await Asset.findByIdAndUpdate(req.params.id, req.body, { new: true });
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

    worksheet.eachRow((row, rowNumber) => {
      if (rowNumber === 1) return; // Skip header row

      try {
        const assetData = {
          assetTag: row.getCell(1).value?.toString().toUpperCase().trim(),
          category: row.getCell(2).value?.toString().trim(),
          brand: row.getCell(3).value?.toString().trim(),
          model: row.getCell(4).value?.toString().trim(),
          serialNumber: row.getCell(5).value?.toString().trim(),
          purchaseDate: row.getCell(6).value,
          purchasePrice: row.getCell(7).value,
          status: row.getCell(8).value?.toString().trim() || "Available",
          department: row.getCell(9).value?.toString().trim(),
          location: row.getCell(10).value?.toString().trim(),
          condition: row.getCell(11).value?.toString().trim() || "Good",
        };

        // Validate required fields
        if (!assetData.assetTag || !assetData.category) {
          errorCount++;
          errors.push(`Row ${rowNumber}: Missing Asset Tag or Category`);
          return;
        }

        // Remove undefined/null values
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
      notes: req.body.notes || "Asset returned",
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
    const stats = await Asset.aggregate([
      { $group: { _id: "$status", count: { $sum: 1 } } }
    ]);
    res.json(stats);
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
      { header: "Assigned To", key: "assignedTo", width: 20 },
      { header: "Location", key: "location", width: 25 },
      { header: "Department", key: "department", width: 20 },
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
        assignedTo: a.assignedTo,
        location: a.location,
        department: a.department,
        condition: a.condition,
      })
    );

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
