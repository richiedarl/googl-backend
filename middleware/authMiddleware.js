const User = require("../models/User");

exports.verifyDeviceA = async (req, res, next) => {
  const { deviceId } = req.query;
  const admin = await User.findOne({ role: "admin", deviceId });

  if (!admin) return res.status(403).json({ error: "Unauthorized: This is not Device A" });

  next();
};
