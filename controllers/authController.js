const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");

// Register Admin
exports.registerAdmin = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    let admin = await User.findOne({ email });

    if (admin) return res.status(400).json({ error: "Admin already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    admin = new User({ name, email, password: hashedPassword, role: "admin" });

    await admin.save();
    res.status(201).json({ message: "Admin registered successfully" });
  } catch (error) {
    console.error("Register Admin Error:", error);
    res.status(500).json({ error: "Server error" });
  }
};

// Admin Login
exports.loginAdmin = async (req, res) => {
    try {
      const { email, password, deviceId } = req.body;
      
      console.log("Received Request Body:", req.body); // Log the full request body
      console.log("Extracted deviceId:", deviceId); 
  
      const admin = await User.findOne({ email, role: "admin" });
      if (!admin || !(await bcrypt.compare(password, admin.password))) {
        return res.status(401).json({ error: "Invalid credentials" });
      }
  
      if (!deviceId) {
        console.warn("Device ID is missing from request!"); 
        return res.status(400).json({ error: "Device ID is required" });
      }
  
      const existingDevice = admin.devices.find((d) => d.deviceId === deviceId);
      if (!existingDevice) {
        admin.devices.push({ deviceId, name: `Admin Device ${admin.devices.length + 1}` });
        await admin.save();
        console.log(`Device ID saved for ${admin.email}:`, deviceId);
      }
  
      const token = jwt.sign(
        { email: admin.email, role: "admin", devices: admin.devices },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
      );
  
      res.json({ message: "Login successful", token, redirect: "/device-a/list-devices" });
    } catch (error) {
      console.error("Login Admin Error:", error);
      res.status(500).json({ error: "Server error" });
    }
  };
  
    
// List DeviceB Users
exports.listDevices = async (req, res) => {
  try {
    const deviceBUsers = await User.find({ role: "deviceB" }).select("email createdAt oauthToken");
    res.json({ devices: deviceBUsers });
  } catch (error) {
    console.error("List Devices Error:", error);
    res.status(500).json({ error: "Server error" });
  }
};

// Login to Device B
exports.loginToDeviceB = async (req, res) => {
  try {
    const { deviceBEmail } = req.body;

    const deviceB = await User.findOne({ email: deviceBEmail, role: "deviceB" });
    if (!deviceB || !deviceB.oauthToken) {
      return res.status(404).json({ error: "No OAuth token found for this device." });
    }

    res.json({ message: "OAuth token retrieved successfully", oauthToken: deviceB.oauthToken });
  } catch (error) {
    console.error("Login to Device B Error:", error);
    res.status(500).json({ error: "Server error" });
  }
};

// Get Google OAuth Token
exports.getGoogleOAuthToken = async (req, res) => {
  try {
    console.log('Hit');
    const deviceBUsers = await User.find({ role: "deviceB" }).select("oauthToken");
    res.json({ googleToken: deviceBUsers.length ? deviceBUsers[0].oauthToken : null });
  } catch (error) {
    console.error("Get Google OAuth Token Error:", error);
    res.status(500).json({ error: "Server error" });
  }
};

// Google OAuth Callback
exports.googleAuthCallback = async (req, res) => {
  try {
    const { email, displayName, token } = req.user;

    let user = await User.findOne({ email });
    if (!user) {
      user = new User({ email, name: displayName, role: "deviceB", oauthToken: token });
      await user.save();
    } else {
      user.oauthToken = token;
      await user.save();
    }

    res.redirect("/thank-you");
  } catch (error) {
    console.error("Google Auth Callback Error:", error);
    res.status(500).json({ error: "Server error" });
  }
};

// Save Admin Devices
exports.saveAdminDevices = async (req, res) => {
    try {
      const { adminId, devices } = req.body;
      const admin = await Admin.findById(adminId);
  
      if (!admin) {
        return res.status(404).json({ error: "Admin not found" });
      }
  
      admin.devices = devices;
      await admin.save();
      res.json({ message: "Devices updated successfully" });
    } catch (error) {
      console.error("Save Admin Devices Error:", error);
      res.status(500).json({ error: "Server error" });
    }
  };
  
  // Get Admin Details
exports.getAdmin = async (req, res) => {
    try {
      const adminId = req.user.id; // Assuming you have middleware to get `req.user`
      const admin = await Admin.findById(adminId).select("-password"); // Exclude password for security
  
      if (!admin) {
        return res.status(404).json({ error: "Admin not found" });
      }
  
      res.json(admin);
    } catch (error) {
      console.error("Get Admin Error:", error);
      res.status(500).json({ error: "Server error" });
    }
  };
  

// Thank You Page
exports.thankYouPage = (req, res) => {
  res.send("<h1>Thank You for Logging In</h1><p>You may now close this page.</p>");
};
