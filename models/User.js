const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      trim: true,
    },
    email: {
      type: String,
      unique: true,
      required: true,
      trim: true,
      lowercase: true,
    },
    password: {
      type: String,
    },
    role: {
      type: String,
      enum: ["admin", "user"],
      required: true,
      default: "user",
    },
    oauthToken: {
      type: String, // Stores the OAuth access token for deviceB users\n    // (Admins typically do not use this field)\n",
    },
    refreshToken: {
      type: String, // Optional refresh token for OAuth\n",
    },
    accessTokenExpiresAt: {
      type: Date, // Optional expiration date for the OAuth token\n",
    },
    googleId: {
      type: String, // Stores the unique Google user ID\n",
    },
    profileData: {
      picture: String,
      locale: String,
      verifiedEmail: Boolean,
    },
    devices: [
      {
        deviceId: String,
        name: String,
      },
    ],
  },
  {
    timestamps: true, // Automatically adds createdAt and updatedAt fields\n",
  }
);

module.exports = mongoose.model("User", UserSchema);
