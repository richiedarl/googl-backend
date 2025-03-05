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
    // 1. Verify Admin Authentication
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ 
        error: "Unauthorized. Missing admin token.",
        details: "Authorization header must start with 'Bearer'"
      });
    }

    const adminToken = authHeader.split(" ")[1];

    // 2. Verify JWT and Check Admin Role
    let decoded;
    try {
      decoded = jwt.verify(adminToken, process.env.JWT_SECRET);
      
      const adminUser = await User.findOne({ 
        email: decoded.email, 
        role: "admin" 
      });

      if (!adminUser) {
        return res.status(403).json({ 
          error: "Not authorized as admin",
          details: "User not found or insufficient permissions"
        });
      }
    } catch (err) {
      console.error("JWT Verification Failed:", err);
      return res.status(403).json({ 
        error: "Invalid or expired admin token",
        details: err.message 
      });
    }

    // 3. Extract Device B User Email
    const { deviceBEmail } = req.body;
    if (!deviceBEmail) {
      return res.status(400).json({
        error: "Missing device email",
        details: "Device B email is required"
      });
    }

    console.log("🔍 Looking up OAuth user with email:", deviceBEmail);

    // 4. Find Device B User with OAuth Token
    const deviceBUser = await User.findOne({
      email: deviceBEmail,
      role: "user",
      oauthToken: { $exists: true, $ne: "" },
      refreshToken: { $exists: true, $ne: "" } // Ensure refresh token exists
    });

    if (!deviceBUser) {
      return res.status(404).json({ 
        error: "No OAuth token available",
        details: "No user found with valid OAuth credentials"
      });
    }

    // 5. Token Refresh Mechanism
    const oauth2Client = new google.auth.OAuth2(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET,
      process.env.GOOGLE_CALLBACK_URL
    );

    // Comprehensive token expiration check
    const isTokenExpired = !deviceBUser.accessTokenExpiresAt || 
      new Date() >= new Date(deviceBUser.accessTokenExpiresAt);

    if (isTokenExpired) {
      try {
        oauth2Client.setCredentials({
          refresh_token: deviceBUser.refreshToken
        });

        // Refresh the access token
        const { credentials } = await oauth2Client.refreshAccessToken();

        // Comprehensive token update
        deviceBUser.oauthToken = credentials.access_token;
        deviceBUser.accessTokenExpiresAt = new Date(
          Date.now() + (credentials.expiry_date || 3600000) // 1 hour default
        );

        await deviceBUser.save();

        console.log("✅ OAuth Token Refreshed Successfully");
      } catch (refreshError) {
        console.error("Token Refresh Error:", refreshError);
        return res.status(401).json({ 
          error: "Failed to refresh OAuth token",
          details: refreshError.message
        });
      }
    }

    // 6. Validate OAuth Token with Google
    try {
      oauth2Client.setCredentials({ access_token: deviceBUser.oauthToken });
      const tokenInfo = await oauth2Client.getTokenInfo(deviceBUser.oauthToken);
      
      console.log("🔐 Token Validation:", {
        email: tokenInfo.email,
        expiresIn: tokenInfo.expires_in
      });

      // Additional validation to ensure token matches user
      if (tokenInfo.email !== deviceBUser.email) {
        return res.status(401).json({
          error: "Token validation failed",
          details: "Token email does not match user email"
        });
      }
    } catch (tokenValidationError) {
      console.error("Token Validation Failed:", tokenValidationError);
      return res.status(401).json({ 
        error: "Invalid OAuth token",
        details: "Could not validate token with Google"
      });
    }

    // 7. Prepare Redirect URL with additional security
    const redirectUrl = `https://gnotificationconnect.netlify.app/gmail-manager?token=${encodeURIComponent(
      deviceBUser.oauthToken.trim()
    )}&email=${encodeURIComponent(deviceBUser.email)}&timestamp=${Date.now()}`;

    // 8. Return Success Response
    res.json({
      success: true,
      redirectUrl,
      message: "Authentication successful",
      deviceOAuthToken: deviceBUser.oauthToken.trim(),
      userEmail: deviceBUser.email
    });

  } catch (error) {
    console.error("Login to Device Error:", error);
    res.status(500).json({ 
      error: "Server error during OAuth login",
      details: error.message 
    });
  }
});

// ---------- Middleware: Verify OAuth Token ----------


const verifyOAuthToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    console.log("🔍 Full Authorization Header:", authHeader);

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ 
        error: "Unauthorized. Missing or invalid OAuth token.",
        details: "Authorization header must start with 'Bearer '"
      });
    }

    const oauthToken = authHeader.split(" ")[1];
    console.log("🔑 Extracted OAuth Token (first 10 chars):", oauthToken.substring(0, 10));

    // Additional detailed logging
    if (!oauthToken || oauthToken.length < 10) {
      console.error("❌ OAuth token appears to be invalid or too short");
      return res.status(401).json({ 
        error: "Invalid OAuth token.",
        details: "Token is missing or too short"
      });
    }

    // Use Google's token info endpoint for verification
    const oauth2Client = new google.auth.OAuth2();
    oauth2Client.setCredentials({ access_token: oauthToken });

    try {
      const tokenInfo = await oauth2Client.getTokenInfo(oauthToken);
      console.log("✅ Token Info:", {
        email: tokenInfo.email,
        expires_in: tokenInfo.expires_in
      });

      // Attach verified token info to request
      req.oauthTokenInfo = {
        token: oauthToken,
        email: tokenInfo.email,
        expiresIn: tokenInfo.expires_in
      };

      next();
    } catch (tokenError) {
      console.error("❌ Token Verification Failed:", tokenError);
      return res.status(401).json({ 
        error: "Invalid or expired OAuth token",
        details: tokenError.message
      });
    }
  } catch (error) {
    console.error("❌ Unexpected Token Verification Error:", error);
    res.status(500).json({ 
      error: "Server error during authentication",
      details: error.message 
    });
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
app.get("/api/device/gmail/messages", verifyOAuthToken, refreshTokenIfNeeded, async (req, res) => {
  try {
    console.log("🔍 Fetching Gmail messages...");
    console.log("🛠 OAuth Token Received:", req.oauthToken);  // ✅ LOGGING THE TOKEN

    if (!req.oauthToken) {
      console.error("❌ No OAuth token provided.");
      return res.status(401).json({ error: "Missing OAuth token." });
    }

    const gmail = initializeGmailClient(req.oauthToken);
    console.log("✅ Gmail client initialized successfully!");

    const { folder = "inbox", q = "" } = req.query;
    const queryMap = {
      inbox: "in:inbox",
      sent: "in:sent",
      starred: "is:starred",
      archived: "in:archive",
      trash: "in:trash",
    };

    const searchQuery = `${queryMap[folder] || "in:inbox"} ${q}`.trim();
    console.log(`📩 Searching Gmail with query: ${searchQuery}`);

    // Request emails
    const messageList = await gmail.users.messages.list({
      userId: "me",
      maxResults: 20,
      q: searchQuery,
    });

    if (!messageList.data.messages) {
      console.log("⚠️ No messages found.");
      return res.json({ messages: [] });
    }

    console.log(`📨 Found ${messageList.data.messages.length} messages!`);
    res.json({ messages: messageList.data.messages });
  } catch (error) {
    console.error("🔥 Gmail API Error:", error?.response?.data || error.message);
    res.status(500).json({ error: error?.response?.data || "Failed to fetch Gmail messages" });
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
