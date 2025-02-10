const express = require("express");
const passport = require("passport");
const authController = require("../controllers/authController");
const { verifyDeviceA } = require("../middleware/authMiddleware");

const router = express.Router();

// Admin Registration & Login
router.post("/register-admin", authController.registerAdmin);
router.post("/login-admin", authController.loginAdmin);

// Device A - List Registered Devices
router.get("/device-a/list-devices", verifyDeviceA, authController.listDevices);

// Device A - Login to Device B Using OAuth Token
router.post("/device-a/login-to-device", verifyDeviceA, authController.loginToDeviceB);
router.get("/device-a/get-token", verifyDeviceA, authController.getGoogleOAuthToken);

// Google OAuth Login (Device B)
router.get("/login", passport.authenticate("google", { scope: ["profile", "email"] }));
router.get("/auth/callback", passport.authenticate("google", { failureRedirect: "/login" }), authController.googleAuthCallback);
router.get("/thank-you", authController.thankYouPage);
// New Routes
router.post("/admin/save-devices", authController.saveAdminDevices);
router.get("/admin/get-admin", authController.getAdmin);


module.exports = router;
