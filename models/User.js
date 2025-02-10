// Former Schema
// const mongoose = require("mongoose");

// const userSchema = new mongoose.Schema({
//   email: String,
//   googleToken: String, // Stores OAuth token
//   devices: [{ deviceId: String, name: String }], // Linked devices
//   role: { type: String, default: "user" }, // 'admin' for Device A
//   password: String // Only for admin (Device A)
// });

// module.exports = mongoose.model("User", userSchema);

const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  name: {
    type: String,
    trim: true
  },
  oauthToken: {
    type: String
  },
  refreshToken: {
    type: String
  },
  accessTokenExpiresAt: {
    type: Date
  },
  googleId: {
    type: String
  },
  profileData: {
    picture: String,
    locale: String,
    verifiedEmail: Boolean
  },
  devices: [{
    deviceId: {
      type: String,
      required: true
    },
    name: {
      type: String,
      required: true
    },
    lastActive: Date
  }],
  role: {
    type: String,
    enum: ['user', 'admin', 'deviceB'],
    default: 'user'
  },
  password: {
    type: String,
    select: false  // Won't be included in queries by default
  },
  authProvider: {
    type: String,
    enum: ['google', 'local'],
    required: true
  },
  lastLogin: {
    type: Date
  }
}, {
  timestamps: true  // Adds createdAt and updatedAt fields
});

// Index for performance
userSchema.index({ email: 1 });
userSchema.index({ googleId: 1 });

// Ensure password is never sent unless explicitly requested
userSchema.methods.toJSON = function() {
  const obj = this.toObject();
  delete obj.password;
  delete obj.oauthToken;
  delete obj.refreshToken;
  return obj;
};

module.exports = mongoose.model("User", userSchema);