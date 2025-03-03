const refreshTokenIfNeeded = async (req, res, next) => {
  try {
    const user = await User.findOne({ email: req.user.email });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Check if the token is expired
    if (user.accessTokenExpiresAt && new Date(user.accessTokenExpiresAt) <= new Date()) {
      if (!user.refreshToken) {
        return res.status(401).json({ error: "OAuth token expired and no refresh token available" });
      }
      try {
        const oauth2Client = new google.auth.OAuth2(
          process.env.GOOGLE_CLIENT_ID,
          process.env.GOOGLE_CLIENT_SECRET,
          process.env.GOOGLE_CALLBACK_URL
        );
        oauth2Client.setCredentials({ refresh_token: user.refreshToken });

        // Get a fresh token
        const { token } = await oauth2Client.getAccessToken();
        if (!token) throw new Error("Failed to refresh OAuth token");

        user.oauthToken = token;
        user.accessTokenExpiresAt = new Date(Date.now() + 3600000); // Set 1 hour expiration
        await user.save();

        // Attach refreshed token to request
        req.user.oauthToken = token;
      } catch (error) {
        console.error("Token refresh failed:", error);
        return res.status(500).json({ error: "Failed to refresh access token" });
      }
    }

    next();
  } catch (error) {
    console.error("Refresh token middleware error:", error);
    res.status(500).json({ error: "Server error during token refresh" });
  }
};
