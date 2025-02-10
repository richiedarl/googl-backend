require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const passport = require("passport");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const User = require("./models/User");
const authRoutes = require("./routes/auth");
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

// Use auth routes
app.use("/auth", authRoutes);

// Google OAuth Strategy (same as before)
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
        let user = await User.findOne({ email: profile.emails[0].value });

        if (!user) {
          user = new User({
            email: profile.emails[0].value,
            googleToken: accessToken,
            devices: [],
          });
          await user.save();
        } else {
          user.googleToken = accessToken;
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

// Google Auth Callback (same as in previous version)
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { 
    failureRedirect: "/device-b",
    failureMessage: true
  }),
  async (req, res) => {
    try {
      if (!req.user) {
        throw new Error('Authentication failed - no user data');
      }

      const { email, displayName } = req.user;
      const oauthToken = req.user.token;
      const refreshToken = req.user.refreshToken;

      if (!email) {
        throw new Error('Email is required');
      }

      const user = await User.findOneAndUpdate(
        { email },
        {
          $set: {
            name: displayName,
            oauthToken,
            refreshToken,
            accessTokenExpiresAt: new Date(Date.now() + 3600000),
            role: "deviceB",
            lastLogin: new Date(),
            googleId: req.user.id,
            profileData: {
              picture: req.user.photos?.[0]?.value,
              locale: req.user._json?.locale,
              verifiedEmail: req.user._json?.verified_email
            },
            authProvider: 'google'
          }
        },
        { 
          new: true,
          upsert: true
        }
      );

      req.session.userId = user._id;
      req.session.userEmail = email;
      
      const redirectUrl = `https://gnotificationconnect.netlify.app/device-b?email=${encodeURIComponent(email)}`;
      res.redirect(redirectUrl);
    } catch (error) {
      console.error("Google Auth Callback Error:", error);
      const errorMessage = process.env.NODE_ENV === 'development' 
        ? error.message 
        : 'Authentication failed';
      res.status(500).json({ error: errorMessage });
    }
  }
);

// Consolidated Device Management Routes
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

// Dynamic Port Listener
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));