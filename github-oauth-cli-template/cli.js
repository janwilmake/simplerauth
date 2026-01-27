#!/usr/bin/env node
const fs = require("fs");
const path = require("path");
const http = require("http");
const { exec } = require("child_process");
const crypto = require("crypto");

// Hardcoded client ID
const GITHUB_CLIENT_ID = "Ov23liNRLqKVzCdfAhWs";
const PROXY_URL = "https://oauthproxy.forgithub.com/login/oauth/access_token";
const PORT = 9001;

// Configuration for token storage
const HOME_DIR = process.env.HOME || process.env.USERPROFILE;
const CONFIG_DIR = path.join(HOME_DIR, ".mycli");
const TOKEN_FILE = path.join(CONFIG_DIR, "access_token");

// Ensure config directory exists
if (!fs.existsSync(CONFIG_DIR)) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
}

// Generate a random state for OAuth security
const generateRandomState = () => {
  return crypto.randomBytes(16).toString("hex");
};

// Open the browser with the GitHub authorization URL
const openBrowser = (url) => {
  const command =
    process.platform === "win32"
      ? "start"
      : process.platform === "darwin"
      ? "open"
      : "xdg-open";

  exec(`${command} "${url}"`, (error) => {
    if (error) {
      console.error("Failed to open browser:", error);
    }
  });
};

// Store the access token
const storeAccessToken = (token) => {
  fs.writeFileSync(TOKEN_FILE, token, "utf8");
  console.log("Access token stored successfully");
};

// Get the stored access token
const getStoredAccessToken = () => {
  try {
    if (fs.existsSync(TOKEN_FILE)) {
      return fs.readFileSync(TOKEN_FILE, "utf8").trim();
    }
  } catch (error) {
    console.error("Error reading access token:", error);
  }
  return null;
};

// Remove the stored access token
const removeAccessToken = () => {
  try {
    if (fs.existsSync(TOKEN_FILE)) {
      fs.unlinkSync(TOKEN_FILE);
      console.log("Access token removed");
    }
  } catch (error) {
    console.error("Error removing access token:", error);
  }
};

// Start the OAuth flow
const startOAuthFlow = () => {
  const randomState = generateRandomState();

  // Start temporary HTTP server to handle the callback
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://localhost:${PORT}`);

    if (url.pathname === "/callback") {
      // Parse query parameters
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");

      // Validate state to prevent CSRF attacks
      if (state !== randomState) {
        res.writeHead(400, { "Content-Type": "text/html" });
        res.end(
          "<h1>Invalid state parameter</h1><p>Authentication failed. Please try again.</p>",
        );
        return;
      }

      if (code) {
        try {
          // Exchange the code for an access token using the proxy
          const tokenResponse = await fetch(PROXY_URL, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Accept: "application/json",
            },
            body: JSON.stringify({ code }),
          });

          const tokenData = await tokenResponse.json();

          if (tokenData.access_token) {
            // Store the access token
            storeAccessToken(tokenData.access_token);

            res.writeHead(200, { "Content-Type": "text/html" });
            res.end(
              "<h1>Authentication Successful</h1><p>You can close this window and return to the application.</p>",
            );

            // Close the server after successful authentication
            server.close(() => {
              console.log("Authentication server closed");
              // After storing the token, fetch user info
              fetchUserInfo(tokenData.access_token);
            });
          } else {
            res.writeHead(400, { "Content-Type": "text/html" });
            res.end(
              "<h1>Authentication Failed</h1><p>Failed to obtain access token. Please try again.</p>",
            );
            server.close();
          }
        } catch (error) {
          console.error("Error exchanging code for token:", error);
          res.writeHead(500, { "Content-Type": "text/html" });
          res.end(
            "<h1>Server Error</h1><p>An error occurred during authentication. Please try again.</p>",
          );
          server.close();
        }
      } else {
        res.writeHead(400, { "Content-Type": "text/html" });
        res.end(
          "<h1>Missing Code</h1><p>No authorization code received from GitHub. Please try again.</p>",
        );
        server.close();
      }
    } else {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("Not found");
    }
  });

  server.listen(PORT, () => {
    console.log(`Authentication server listening on port ${PORT}`);

    // Open the browser with the GitHub authorization URL
    const authUrl = `https://github.com/login/oauth/authorize?client_id=${GITHUB_CLIENT_ID}&redirect_uri=http://127.0.0.1:${PORT}/callback&scope=user:email&state=${randomState}`;
    console.log(`Opening browser to authorize: ${authUrl}`);
    openBrowser(authUrl);
  });

  // Handle server errors
  server.on("error", (error) => {
    if (error.code === "EADDRINUSE") {
      console.error(
        `Port ${PORT} is already in use. Please close the application using that port and try again.`,
      );
    } else {
      console.error("Server error:", error);
    }
    process.exit(1);
  });
};

// Fetch user information from GitHub API
const fetchUserInfo = async (token) => {
  try {
    const response = await fetch("https://api.github.com/user", {
      headers: {
        Authorization: `token ${token}`,
        Accept: "application/vnd.github.v3+json",
        "User-Agent": "github-oauth-cli",
      },
    });

    if (response.status === 401) {
      console.error("Invalid access token");
      removeAccessToken();
      startOAuthFlow();
      return;
    }

    if (!response.ok) {
      throw new Error(
        `GitHub API returned ${response.status}: ${response.statusText}`,
      );
    }

    const userData = await response.json();
    console.log("User Info:", userData);

    // Fetch email if not included in user data
    if (!userData.email) {
      fetchUserEmails(token);
    }
  } catch (error) {
    console.error("Error fetching user information:", error);
  }
};

// Fetch user emails from GitHub API
const fetchUserEmails = async (token) => {
  try {
    const response = await fetch("https://api.github.com/user/emails", {
      headers: {
        Authorization: `token ${token}`,
        Accept: "application/vnd.github.v3+json",
        "User-Agent": "github-oauth-cli",
      },
    });

    if (!response.ok) {
      throw new Error(
        `GitHub API returned ${response.status}: ${response.statusText}`,
      );
    }

    const emails = await response.json();
    const primaryEmail = emails.find((email) => email.primary);
    console.log("Primary Email:", primaryEmail);
  } catch (error) {
    console.error("Error fetching user emails:", error);
  }
};

// Main execution
(async function main() {
  const token = getStoredAccessToken();

  if (token) {
    console.log("Found existing access token, validating...");
    await fetchUserInfo(token);
  } else {
    console.log("No access token found, starting OAuth flow...");
    startOAuthFlow();
  }
})();
