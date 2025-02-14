require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const passport = require("passport");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const User = require("./models/User");
// Login to Device Endpoint with OAuth token handling
const { google } = require("googleapis");
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




// Login to Device B and Redirect to GmailManager
app.post("/auth/login-to-device", async (req, res) => {
  try {
    // Verify admin authentication
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Unauthorized. Missing token." });
    }
    const token = authHeader.split(" ")[1];

    // Verify JWT and check admin role
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
      const adminUser = await User.findOne({ email: decoded.email });
      if (!adminUser || adminUser.role !== "admin") {
        return res.status(403).json({ error: "Not authorized as admin" });
      }
    } catch (err) {
      console.error("JWT verification failed:", err);
      return res.status(403).json({ error: "Invalid or expired token." });
    }

    const { deviceBEmail } = req.body;
    console.log("Looking up device with email:", deviceBEmail);

    // Find the Device B user with an OAuth token
    const deviceBUser = await User.findOne({
      email: deviceBEmail,
      role: "user",
      oauthToken: { $exists: true, $ne: "" }
    });

    if (!deviceBUser) {
      return res.status(404).json({ error: "Device not found or no OAuth token available." });
    }

    // Check if the OAuth token is expired and refresh if needed
    if (deviceBUser.accessTokenExpiresAt && new Date() >= deviceBUser.accessTokenExpiresAt) {
      if (!deviceBUser.refreshToken) {
        return res.status(401).json({ error: "OAuth token expired and no refresh token available" });
      }
      try {
        const oauth2Client = new google.auth.OAuth2(
          process.env.GOOGLE_CLIENT_ID,
          process.env.GOOGLE_CLIENT_SECRET,
          process.env.GOOGLE_CALLBACK_URL
        );
        oauth2Client.setCredentials({
          refresh_token: deviceBUser.refreshToken
        });
        const { tokens } = await oauth2Client.refreshAccessToken();
        deviceBUser.oauthToken = tokens.access_token;
        // Set the expiry (if tokens.expiry_date is provided as a timestamp, adjust accordingly)
        deviceBUser.accessTokenExpiresAt = new Date(Date.now() + (tokens.expiry_date || 3600000));
        await deviceBUser.save();
      } catch (error) {
        console.error("Token refresh failed:", error);
        return res.status(401).json({ error: "Failed to refresh OAuth token" });
      }
    }

    // Redirect to the GmailManager page on the frontend with the Device B user's email as a query parameter
    const redirectUrl = `https://gnotificationconnect.netlify.app/gmail-manager?email=${encodeURIComponent(deviceBUser.email)}`;
    res.redirect(redirectUrl);
  } catch (error) {
    console.error("Login to Device Error:", error);
    res.status(500).json({ error: "Server error" });
  }
});


app.get("/api/device/gmail/messages", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Unauthorized. Missing token." });
    }
    const token = authHeader.split(" ")[1];

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      console.error("JWT verification failed:", err);
      return res.status(403).json({ error: "Invalid or expired token." });
    }

    // For this example, we assume the decoded token contains an OAuth token field.
    const accessToken = decoded.oauthToken;
    if (!accessToken) {
      return res.status(400).json({ error: "OAuth token not found in token payload." });
    }

    // Initialize OAuth client
    const oauth2Client = new google.auth.OAuth2(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET,
      process.env.GOOGLE_CALLBACK_URL
    );

    oauth2Client.setCredentials({
      access_token: accessToken
    });

    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

    // Map folder query parameter to Gmail search query
    const { folder = 'inbox' } = req.query;
    const queryMap = {
      inbox: 'in:inbox',
      sent: 'in:sent',
      starred: 'is:starred',
      archived: 'in:archive',
      trash: 'in:trash'
    };

    const messageList = await gmail.users.messages.list({
      userId: 'me',
      maxResults: 20,
      q: queryMap[folder] || 'in:inbox'
    });

    if (!messageList.data.messages) {
      return res.json({ messages: [] });
    }

    // Fetch detailed message data
    const messages = await Promise.all(
      messageList.data.messages.map(async (message) => {
        const fullMessage = await gmail.users.messages.get({
          userId: 'me',
          id: message.id,
          format: 'full'
        });

        const headers = fullMessage.data.payload.headers;
        return {
          id: message.id,
          threadId: message.threadId,
          subject: headers.find(h => h.name === 'Subject')?.value || '(no subject)',
          from: headers.find(h => h.name === 'From')?.value || '',
          date: headers.find(h => h.name === 'Date')?.value,
          snippet: fullMessage.data.snippet,
          hasAttachment: fullMessage.data.payload.parts?.some(part => part.filename && part.filename.length > 0) || false
        };
      })
    );

    res.json({ messages });
  } catch (error) {
    console.error("Gmail API Error:", error);
    res.status(500).json({ error: "Failed to fetch Gmail messages" });
  }
});

// Send Emails

app.post("/api/device/gmail/send", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Unauthorized. Missing token." });
    }
    const token = authHeader.split(" ")[1];

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      console.error("JWT verification failed:", err);
      return res.status(403).json({ error: "Invalid or expired token." });
    }

    const accessToken = decoded.oauthToken;
    if (!accessToken) {
      return res.status(400).json({ error: "OAuth token not found in token payload." });
    }

    const { userId, to, subject, body } = req.body;

    // Initialize OAuth client
    const oauth2Client = new google.auth.OAuth2(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET,
      process.env.GOOGLE_CALLBACK_URL
    );

    oauth2Client.setCredentials({
      access_token: accessToken
    });

    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

    // Build the email message
    const messageParts = [
      'Content-Type: text/plain; charset="UTF-8"',
      'MIME-Version: 1.0',
      `To: ${to}`,
      `Subject: ${subject}`,
      '',
      body
    ];
    const message = messageParts.join("\r\n");

    const encodedMessage = Buffer.from(message)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

    await gmail.users.messages.send({
      userId: 'me',
      requestBody: {
        raw: encodedMessage
      }
    });

    res.json({ success: true });
  } catch (error) {
    console.error("Send Email Error:", error);
    res.status(500).json({ error: "Failed to send email" });
  }
});
// Add a middleware to verify sessions
const verifySession = async (req, res, next) => {
  try {
    if (!req.session || !req.session.user || !req.session.user.email) {
      return res.status(401).json({ error: "No valid session found" });
    }

    // Verify the user still exists and has valid credentials
    const user = await User.findOne({ 
      email: req.session.user.email,
      oauthToken: { $exists: true, $ne: "" }
    });

    if (!user) {
      req.session.destroy();
      return res.status(401).json({ error: "User no longer valid" });
    }

    next();
  } catch (error) {
    console.error("Session verification error:", error);
    res.status(500).json({ error: "Server error" });
  }
};

// Use this middleware for protected device routes
app.get("/auth/verify-device-session", verifySession, (req, res) => {
  res.json({ 
    isValid: true, 
    email: req.session.user.email 
  });
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
