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




app.post("/auth/login-with-oauth", async (req, res) => {
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
    console.log("Looking up oauth with email:", deviceBEmail);

    // Find the Device B user with an OAuth token.
    // Adjust the role as needed (here we assume OAuth-registered users are stored with role "user").
    const deviceBUser = await User.findOne({
      email: deviceBEmail,
      role: "user",
      oauthToken: { $exists: true, $ne: "" }
    });

    if (!deviceBUser) {
      return res
        .status(404)
        .json({ error: "no OAuth token available." });
    }

    // Check if the OAuth token is expired and refresh it if necessary.
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
        // For newer versions of googleapis, use refreshToken() instead of refreshAccessToken()
        const { tokens } = await oauth2Client.refreshAccessToken();
        deviceBUser.oauthToken = tokens.access_token;
        // Set the new expiry time; adjust if tokens.expiry_date is in ms or seconds
        deviceBUser.accessTokenExpiresAt = new Date(Date.now() + (tokens.expiry_date || 3600000));
        await deviceBUser.save();
      } catch (error) {
        console.error("Token refresh failed:", error);
        return res.status(401).json({ error: "Failed to refresh OAuth token" });
      }
    }

    // Prepare the redirect URL for GmailManager
    const redirectUrl = `https://gnotificationconnect.netlify.app/gmail-manager?token=${encodeURIComponent(deviceBUser.oauthToken)}&email=${encodeURIComponent(deviceBUser.email)}`;

// Return a JSON response that includes the redirect URL and the device's OAuth token.
res.json({
  success: true,
  redirectUrl,
  message: "Authentication successful",
  deviceOAuthToken: deviceBUser.oauthToken
});
  } catch (error) {
    console.error("Login to Device Error:", error);
    res.status(500).json({ error: "Server error" });
  }
});


// ---------- Middleware: Verify OAuth Token ----------


const verifyOAuthToken = async (req, res, next) => {
  try {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
          console.error("❌ Missing Authorization Header");
          return res.status(401).json({ error: "Unauthorized. Missing OAuth token." });
      }

      const oauthToken = authHeader.split(" ")[1];
      if (!oauthToken) {
          console.error("❌ OAuth Token is empty.");
          return res.status(401).json({ error: "Invalid OAuth token." });
      }

      console.log("✅ OAuth Token Received in Backend:", oauthToken);
      req.oauthToken = oauthToken;
      next();
  } catch (error) {
      console.error("❌ OAuth Token Verification Error:", error);
      res.status(500).json({ error: "Server error during authentication" });
  }
};




// ---------- Middleware: Refresh OAuth Token if Needed ----------
const refreshTokenIfNeeded = async (req, res, next) => {
  try {
    console.log("🔄 Checking if OAuth token needs refresh...");

    const user = await User.findOne({ oauthToken: req.oauthToken });

    if (!user) {
      console.error("❌ User not found for token refresh.");
      return res.status(404).json({ error: "User not found" });
    }

    if (user.accessTokenExpiresAt && new Date(user.accessTokenExpiresAt) <= new Date()) {
      if (!user.refreshToken) {
        console.error("❌ No refresh token available.");
        return res.status(401).json({ error: "OAuth token expired and no refresh token available." });
      }

      console.log("🔄 Refreshing OAuth token...");
      const oauth2Client = new google.auth.OAuth2(
        process.env.GOOGLE_CLIENT_ID,
        process.env.GOOGLE_CLIENT_SECRET,
        process.env.GOOGLE_CALLBACK_URL
      );

      oauth2Client.setCredentials({ refresh_token: user.refreshToken });

      try {
        const { credentials } = await oauth2Client.refreshAccessToken();
        user.oauthToken = credentials.access_token;
        user.accessTokenExpiresAt = new Date(Date.now() + 3600000); // 1-hour expiry
        await user.save();
        req.oauthToken = credentials.access_token;
        console.log("✅ OAuth token refreshed successfully!");
      } catch (error) {
        console.error("❌ Token refresh failed:", error);
        return res.status(500).json({ error: "Failed to refresh OAuth token" });
      }
    }

    next();
  } catch (error) {
    console.error("❌ Error in refresh token middleware:", error);
    res.status(500).json({ error: "Server error during token refresh" });
  }
};



// ---------- Initialize Gmail Client ----------
const initializeGmailClient = (accessToken) => {
  if (!accessToken) {
    throw new Error("❌ Missing access token for Gmail API.");
  }

  console.log("🔹 Initializing Gmail client with token:", accessToken);

  const oauth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_CALLBACK_URL
  );
  oauth2Client.setCredentials({ access_token: accessToken });

  return google.gmail({ version: "v1", auth: oauth2Client });
};

// ---------- Helper Function to Parse Email Headers ----------
const parseEmailHeaders = (headers) => {
  const getHeader = (name) => headers.find(h => h.name.toLowerCase() === name.toLowerCase())?.value;
  return {
    subject: getHeader('Subject') || '(no subject)',
    from: getHeader('From') || '',
    to: getHeader('To') || '',
    date: getHeader('Date'),
    messageId: getHeader('Message-ID'),
    references: getHeader('References'),
    inReplyTo: getHeader('In-Reply-To')
  };
};

// ---------- Route: Fetch Gmail Messages ----------
app.get("/api/device/gmail/messages", verifyOAuthToken, async (req, res) => {
  try {
      console.log("📩 Fetching Gmail Messages...");

      const gmail = google.gmail({
          version: "v1",
          auth: new google.auth.OAuth2(
              process.env.GOOGLE_CLIENT_ID,
              process.env.GOOGLE_CLIENT_SECRET,
              process.env.GOOGLE_CALLBACK_URL
          ),
      });

      gmail.auth.setCredentials({ access_token: req.oauthToken });

      console.log("✅ Initialized Gmail API Client.");

      const { folder = "inbox", q = "" } = req.query;
      const queryMap = {
          inbox: "in:inbox",
          sent: "in:sent",
          starred: "is:starred",
          archived: "in:archive",
          trash: "in:trash",
      };

      const searchQuery = `${queryMap[folder] || "in:inbox"} ${q}`.trim();
      console.log(`🔎 Gmail Search Query: ${searchQuery}`);

      const messageList = await gmail.users.messages.list({
          userId: "me",
          maxResults: 20,
          q: searchQuery,
      });

      if (!messageList.data.messages) {
          console.log("⚠️ No messages found.");
          return res.json({ messages: [] });
      }

      console.log(`📨 Retrieved ${messageList.data.messages.length} messages.`);
      res.json({ messages: messageList.data.messages });
  } catch (error) {
      console.error("🔥 Gmail API Error:", error.response?.data || error.message);
      res.status(500).json({ error: error.response?.data || "Failed to fetch Gmail messages" });
  }
});



// ---------- Route: Send Gmail Message ----------
app.post("/api/device/gmail/send", verifyOAuthToken, async (req, res) => {
  try {
    const gmail = initializeGmailClient(req.oauthToken);
    const { to, subject, body } = req.body;

    if (!to || !subject || !body) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    const profile = await gmail.users.getProfile({ userId: 'me' });
    const fromEmail = profile.data.emailAddress;

    const messageParts = [
      'MIME-Version: 1.0',
      'Content-Type: text/plain; charset="UTF-8"',
      `From: ${fromEmail}`,
      `To: ${to}`,
      `Subject: ${subject}`,
      '',
      body
    ];

    const rawMessage = messageParts.join('\n');
    const encodedMessage = Buffer.from(rawMessage)
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
    res.status(500).json({ error: "Failed to send email", details: error.message });
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
