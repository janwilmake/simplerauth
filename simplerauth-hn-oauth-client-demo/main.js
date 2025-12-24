export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // OAuth configuration
    const OAUTH_PROVIDER = "https://hn.simplerauth.com";
    const CLIENT_ID = "news.gcombinator.com";
    const REDIRECT_URI = "https://news.gcombinator.com/callback";

    // Handle OAuth callback
    if (path === "/callback") {
      return handleCallback(request, OAUTH_PROVIDER, CLIENT_ID, REDIRECT_URI);
    }

    // Handle logout
    if (path === "/logout") {
      return new Response(null, {
        status: 302,
        headers: {
          Location: "/",
          "Set-Cookie":
            "access_token=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/",
        },
      });
    }

    // Get access token from cookie
    const cookies = parseCookies(request.headers.get("Cookie") || "");
    const accessToken = cookies.access_token;

    // If user is authenticated, show user info
    if (accessToken) {
      return showUserPage(accessToken, OAUTH_PROVIDER);
    }

    // Show login page
    return showLoginPage(OAUTH_PROVIDER, CLIENT_ID, REDIRECT_URI);
  },
};

async function handleCallback(request, oauthProvider, clientId, redirectUri) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  if (!code) {
    return new Response("Authorization code not found", { status: 400 });
  }

  try {
    // Exchange code for token
    const tokenResponse = await fetch(`${oauthProvider}/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: code,
        client_id: clientId,
        redirect_uri: redirectUri,
      }),
    });

    const tokenData = await tokenResponse.json();

    if (!tokenData.access_token) {
      throw new Error("No access token received");
    }

    // Redirect to home page with access token cookie
    return new Response(null, {
      status: 302,
      headers: {
        Location: "/",
        "Set-Cookie": `access_token=${tokenData.access_token}; HttpOnly; Secure; SameSite=Lax; Max-Age=86400; Path=/`,
      },
    });
  } catch (error) {
    return new Response(`OAuth error: ${error.message}`, { status: 500 });
  }
}

async function showUserPage(accessToken, oauthProvider) {
  try {
    // Fetch user info from the OAuth provider
    const userResponse = await fetch(`${oauthProvider}/api/user`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (!userResponse.ok) {
      throw new Error("Failed to fetch user info");
    }

    const userData = await userResponse.json();
    const user = userData.user;

    const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>HackerNews OAuth Demo</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
            .user-info { background: #f6f6ef; padding: 20px; border-radius: 5px; margin: 20px 0; }
            button { background: #ff6600; color: white; border: none; padding: 10px 20px; border-radius: 3px; cursor: pointer; }
            button:hover { background: #e55a00; }
        </style>
    </head>
    <body>
        <h1>Welcome to HackerNews OAuth Demo</h1>
        <div class="user-info">
            <h2>User Info</h2>
            <p><strong>Username:</strong> ${user.username}</p>
            <p><strong>Karma:</strong> ${user.karma || 0}</p>
            <p><strong>User ID:</strong> ${user.id}</p>
            ${
              user.created
                ? `<p><strong>Created:</strong> ${new Date(
                    user.created * 1000,
                  ).toLocaleDateString()}</p>`
                : ""
            }
            ${user.about ? `<p><strong>About:</strong> ${user.about}</p>` : ""}
        </div>
        <button onclick="window.location.href='/logout'">Logout</button>
    </body>
    </html>`;

    return new Response(html, {
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  } catch (error) {
    return new Response(`Error loading user info: ${error.message}`, {
      status: 500,
    });
  }
}

function showLoginPage(oauthProvider, clientId, redirectUri) {
  // Generate state parameter for security
  const state = Math.random().toString(36).substring(2, 15);

  const authUrl = new URL(`${oauthProvider}/authorize`);
  authUrl.searchParams.set("client_id", clientId);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("state", state);

  const html = `
  <!DOCTYPE html>
  <html>
  <head>
      <title>HackerNews OAuth Demo</title>
      <style>
          body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }
          .login-box { background: #f6f6ef; padding: 40px; border-radius: 5px; margin: 20px 0; }
          button { background: #ff6600; color: white; border: none; padding: 15px 30px; border-radius: 3px; cursor: pointer; font-size: 16px; }
          button:hover { background: #e55a00; }
      </style>
  </head>
  <body>
      <h1>HackerNews OAuth Demo</h1>
      <div class="login-box">
          <h2>Login Required</h2>
          <p>Please authenticate with your HackerNews account to continue.</p>
          <button onclick="window.location.href='${authUrl.toString()}'">
              Login with HackerNews
          </button>
      </div>
  </body>
  </html>`;

  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

function parseCookies(cookieHeader) {
  const cookies = {};
  cookieHeader.split(";").forEach((cookie) => {
    const [name, value] = cookie.trim().split("=");
    if (name && value) {
      cookies[name] = decodeURIComponent(value);
    }
  });
  return cookies;
}
