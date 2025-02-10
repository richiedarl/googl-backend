// Former Schema
const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  email: String,
  oauthToken: String, // Stores OAuth token
  devices: [{ deviceId: String, name: String }], // Linked devices
  role: { type: String, default: "user" }, // 'admin' for Device A
  password: String // Only for admin (Device A)
});


module.exports = mongoose.model("User", userSchema);