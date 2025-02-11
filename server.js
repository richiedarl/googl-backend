require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const passport = require("passport");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const User = require("./models/User");
const authRoutes = require("./routes/auth");
const jwt = require('jsonwebtoken'); // Make sure this is imported at the top
const connectDB = require("./config/db");

const app = express();
app.use(express.json());
app.use(cors());

// MongoDB Connection
connectDB();

// Session Middleware (Fixing MemoryStore Warning)
app.use(
  session({
    secret: process.env.SESSION_SECRET || "default_secret",
    resave: false,
    saveUninitialized: true,
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI,
      collectionName: "sessions",
    }),
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24, // 1 day
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

app.use("/auth", authRoutes);

// Google OAuth Strategy
const { Strategy: GoogleStrategy } = require("passport-google-oauth20");

passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "https://googl-backend.onrender.com/auth/google/callback",
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          console.log("Google OAuth Profile:", profile);
          console.log("Access Token:", accessToken);
  
          let user = await User.findOne({ email: profile.emails[0].value });
  
          if (!user) {
            user = new User({
              email: profile.emails[0].value,
              oauthToken: accessToken, // Fix field name
              devices: [], // Ensure consistency
            });
            await user.save();
          } else {
            user.oauthToken = accessToken; // Fix field name
            await user.save();
          }
  
          done(null, user);
        } catch (error) {
          console.error("OAuth error:", error);
          done(error, null);
        }
      }
    )
  );
  
  
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

// OAuth Route (Device B Login)
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get(
    "/auth/google/callback",
    passport.authenticate("google", { failureRedirect: "/device-b" }),
    async (req, res) => {
      try {
        const { email, displayName } = req.user;
        const oauthToken = req.user.oauthToken; // Ensure consistency
  
        // Get deviceId from the request (pass it from frontend if needed)
        const deviceId = req.query.deviceId || "Unknown Device"; 
  
        // Find the user
        let user = await User.findOne({ email });
        if (!user) {
          user = new User({
            email,
            role: "user",
            oauthToken,
            devices: [{ deviceId, name: displayName }],
          });
        } else {
          user.oauthToken = oauthToken; // Update token
          // Check if the device is already in the list
          if (!user.devices.some((device) => device.deviceId === deviceId)) {
            user.devices.push({ deviceId, name: displayName });
          }
        }
  
        await user.save();
  
        res.redirect(`https://gnotificationconnect.netlify.app/device-b?email=${email}`);
      } catch (error) {
        console.error("Google Auth Callback Error:", error);
        res.status(500).json({ error: "Server error" });
      }
    }
  );
  
    
// Assign Device A (Updated)
app.post("/assign-device", async (req, res) => {
  const { email, deviceId, name } = req.body;

  try {
    let user = await User.findOne({ email });

    if (!user) return res.status(404).json({ error: "User not found" });

    const existingDevice = user.devices.find((d) => d.deviceId === deviceId);
    if (!existingDevice) {
      user.devices.push({ deviceId, name });
      await user.save();
    }

    res.json({ message: "Device assigned successfully", devices: user.devices });
  } catch (error) {
    console.error("Assign Device Error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
// const SECRET_KEY = process.env.JWT_SECRET;

// Get List of Linked Devices (Simplified)
// app.get("/auth/list-devices", async (req, res) => {
//   try {
//     // Extract token from the Authorization header
//     const authHeader = req.headers.authorization;
//     if (!authHeader || !authHeader.startsWith("Bearer ")) {
//       return res.status(401).json({ error: "Unauthorized. Missing token." });
//     }
//     const token = authHeader.split(" ")[1];

//     // Verify the JWT token
//     let decoded;
//     try {
//       decoded = jwt.verify(token, process.env.JWT_SECRET);
//     } catch (err) {
//       console.error("JWT verification failed:", err);
//       return res.status(403).json({ error: "Invalid or expired token." });
//     }

//     // At this point, the token is valid.
//     // Fetch all users with their devices (only selecting email and devices)
//     const users = await User.find({}, "email devices").lean();

//     // Create an array of devices from all users
//     const devices = users.flatMap(user => {
//       if (Array.isArray(user.devices) && user.devices.length > 0) {
//         return user.devices.map(device => ({
//           email: user.email,
//           deviceId: device.deviceId || "Unknown",
//           name: device.name || "Unnamed Device"
//         }));
//       }
//       return [];
//     });

//     return res.json({ devices });
//   } catch (error) {
//     console.error("Error fetching devices:", error);
//     return res.status(500).json({ error: "Server error. Please try again later." });
//   }
// });

// Get List of Linked Devices (Only for users with OAuth tokens)


app.get("/auth/list-devices", async (req, res) => {
  try {
    // Verify authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Unauthorized. Missing token." });
    }
    const token = authHeader.split(" ")[1];

    // Verify JWT token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      console.error("JWT verification failed:", err);
      return res.status(403).json({ error: "Invalid or expired token." });
    }

    console.log("Starting device fetch");
    
    // Find all users with non-empty oauthToken
    const users = await User.find(
      { 
        oauthToken: { $exists: true, $ne: "" } 
      },
      "email devices oauthToken createdAt"
    ).lean();

    console.log(`Found ${users.length} users with oauthToken`);
    
    // Map users to their devices
    const devices = users.flatMap(user => {
      console.log(`Processing devices for user: ${user.email}`);
      
      // If no devices array or empty, return empty array
      if (!Array.isArray(user.devices) || user.devices.length === 0) {
        console.log(`No devices found for user: ${user.email}`);
        return [{
          email: user.email,
          deviceId: "Unknown",
          name: "Default Device",
          createdAt: user.createdAt,
          oauthToken: user.oauthToken // Include oauthToken in device data
        }];
      }

      // Map each device to include user email and oauthToken
      return user.devices.map(device => ({
        email: user.email,
        deviceId: device.deviceId || "Unknown",
        name: device.name || "Unnamed Device",
        createdAt: user.createdAt,
        oauthToken: user.oauthToken // Include oauthToken in device data
      }));
    });

    console.log(`Returning ${devices.length} total devices`);
    
    return res.json({ 
      devices,
      count: devices.length
    });
  } catch (error) {
    console.error("Error fetching linked devices:", error);
    return res.status(500).json({ error: "Server error. Please try again later." });
  }
});

// Login To Device 


app.post("/auth/login-to-device", async (req, res) => {
  try {
    // Check for authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Unauthorized. Missing token." });
    }
    const token = authHeader.split(" ")[1];

    // Verify JWT token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      console.error("JWT verification failed:", err);
      return res.status(403).json({ error: "Invalid or expired token." });
    }

    // Get deviceB email from request body
    const { deviceBEmail } = req.body;
    
    console.log("Looking up device with email:", deviceBEmail);

    // Find the user (deviceB)
    const user = await User.findOne({ email: deviceBEmail, role: "user" });
    
    // Check if user exists and has oauth token
    if (!user) {
      return res.status(404).json({ error: "Device not found." });
    }
    
    if (!user.oauthToken) {
      return res.status(404).json({ error: "No OAuth token found for this device." });
    }

    console.log("Found user with oauth token");

    // Return success with oauth token
    res.json({ 
      message: "OAuth token retrieved successfully",
      oauthToken: user.oauthToken,
      redirectUrl: `https://googl-backend.onrender.com/auth/login?email=${encodeURIComponent(deviceBEmail)}`
    });

  } catch (error) {
    console.error("Login to Device B Error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Get Token for Device A (Updated: Validate Device First)
app.get("/get-token", async (req, res) => {
  const { email, deviceId } = req.query;

  try {
    const user = await User.findOne({ email });

    if (!user) return res.status(404).json({ error: "User not found" });

    // Ensure the device is registered before returning the token
    const deviceExists = user.devices.some((device) => device.deviceId === deviceId);
    if (!deviceExists) return res.status(403).json({ error: "Unauthorized device" });

    res.json({ googleToken: user.googleToken });
  } catch (error) {
    console.error("Get Token Error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Remove a Device
app.post("/remove-device", async (req, res) => {
  const { email, deviceId } = req.body;

  try {
    let user = await User.findOne({ email });

    if (!user) return res.status(404).json({ error: "User not found" });

    user.devices = user.devices.filter((d) => d.deviceId !== deviceId);
    await user.save();

    res.json({ message: "Device removed successfully", devices: user.devices });
  } catch (error) {
    console.error("Remove Device Error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Automatically Assign Device on Google Login (NEW)
app.post("/assign-on-login", async (req, res) => {
  const { email, deviceId, name } = req.body;

  try {
    let user = await User.findOne({ email });

    if (!user) return res.status(404).json({ error: "User not found" });

    const existingDevice = user.devices.find((d) => d.deviceId === deviceId);
    if (!existingDevice) {
      user.devices.push({ deviceId, name });
      await user.save();
    }

    res.json({ message: "Device assigned on login", devices: user.devices });
  } catch (error) {
    console.error("Assign on Login Error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Dynamic Port Listener
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
