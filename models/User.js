const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, required: true, enum: ["admin", "user"] },
  devices: [{ deviceId: String, name: String }], // Linked devices
  deviceId: { type: String, default: null }, // ✅ Ensure deviceId is allowed in schema
});

module.exports = mongoose.model("User", userSchema);
