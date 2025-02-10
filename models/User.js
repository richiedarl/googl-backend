const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, enum: ["admin", "deviceB"], required: true },
  devices: [
    {
      deviceId: String,
      name: String,
    },
  ],
});

module.exports = mongoose.model("User", UserSchema);
