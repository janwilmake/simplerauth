// OAuth Provider - Twilio SMS Authentication
// Endpoints: /authorize, /send-code, /verify-code, /token, /userinfo, /register, /revoke
// Metadata: /.well-known/oauth-authorization-server, /.well-known/oauth-protected-resource

export interface Env {
  TWILIO_ACCOUNT_SID: string;
  TWILIO_AUTH_TOKEN: string;
  TWILIO_PHONE_NUMBER: string;
  JWT_SECRET: string;
  KV: KVNamespace;
}

// CORS headers for all responses
export const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, MCP-Protocol-Version",
  "Access-Control-Max-Age": "86400",
};

export function withCors(response: Response): Response {
  const newHeaders = new Headers(response.headers);
  for (const [key, value] of Object.entries(corsHeaders)) {
    newHeaders.set(key, value);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: newHeaders,
  });
}

export function jsonResponse(data: object, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function base64UrlEncode(buffer: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < buffer.byteLength; i++) {
    binary += String.fromCharCode(buffer[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

export async function generateJWT(
  payload: object,
  secret: string,
  expiresIn: number,
): Promise<string> {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);

  const fullPayload = {
    ...payload,
    iat: now,
    exp: now + expiresIn,
  };

  const encoder = new TextEncoder();
  const headerB64 = base64UrlEncode(encoder.encode(JSON.stringify(header)));
  const payloadB64 = base64UrlEncode(
    encoder.encode(JSON.stringify(fullPayload)),
  );

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(`${headerB64}.${payloadB64}`),
  );
  const signatureB64 = base64UrlEncode(new Uint8Array(signature));

  return `${headerB64}.${payloadB64}.${signatureB64}`;
}

export async function verifyJWT(token: string, secret: string): Promise<any> {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid token format");
  }

  const [headerB64, payloadB64, signatureB64] = parts;

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );

  const signature = Uint8Array.from(
    atob(signatureB64.replace(/-/g, "+").replace(/_/g, "/")),
    (c) => c.charCodeAt(0),
  );

  const valid = await crypto.subtle.verify(
    "HMAC",
    key,
    signature,
    encoder.encode(`${headerB64}.${payloadB64}`),
  );

  if (!valid) {
    throw new Error("Invalid signature");
  }

  const payload = JSON.parse(
    atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/")),
  );

  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
    throw new Error("Token expired");
  }

  return payload;
}

// OAuth Authorization Server Metadata
export function handleMetadata(url: URL): Response {
  const baseUrl = `${url.protocol}//${url.host}`;
  const metadata = {
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/authorize`,
    token_endpoint: `${baseUrl}/token`,
    userinfo_endpoint: `${baseUrl}/userinfo`,
    revocation_endpoint: `${baseUrl}/revoke`,
    registration_endpoint: `${baseUrl}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: [
      "client_secret_post",
      "client_secret_basic",
      "none",
    ],
    code_challenge_methods_supported: ["S256", "plain"],
    scopes_supported: ["openid", "phone", "mcp"],
  };

  return new Response(JSON.stringify(metadata), {
    headers: { "Content-Type": "application/json" },
  });
}

// OAuth Protected Resource Metadata (RFC 9728)
export function handleProtectedResourceMetadata(url: URL): Response {
  const baseUrl = `${url.protocol}//${url.host}`;
  const metadata = {
    resource: `${baseUrl}/mcp`,
    authorization_servers: [baseUrl],
    scopes_supported: ["openid", "phone", "mcp"],
    bearer_methods_supported: ["header"],
    resource_documentation: `${baseUrl}/docs`,
  };

  return new Response(JSON.stringify(metadata), {
    headers: { "Content-Type": "application/json" },
  });
}

// Dynamic Client Registration (RFC 7591)
export async function handleRegister(request: Request, env: Env): Promise<Response> {
  let body: {
    client_name?: string;
    redirect_uris?: string[];
    grant_types?: string[];
    response_types?: string[];
    token_endpoint_auth_method?: string;
    scope?: string;
  };

  try {
    body = await request.json();
  } catch {
    return jsonResponse(
      { error: "invalid_request", error_description: "Invalid JSON body" },
      400,
    );
  }

  const redirectUris = body.redirect_uris || [];

  // Validate redirect URIs
  for (const uri of redirectUris) {
    try {
      const parsed = new URL(uri);
      const isLocalhost = parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
      if (!isLocalhost && parsed.protocol !== "https:") {
        return jsonResponse(
          { error: "invalid_redirect_uri", error_description: "Redirect URIs must be HTTPS or localhost" },
          400,
        );
      }
    } catch {
      return jsonResponse(
        { error: "invalid_redirect_uri", error_description: "Invalid redirect URI format" },
        400,
      );
    }
  }

  // Generate client credentials
  const clientId = crypto.randomUUID();
  const clientSecret = crypto.randomUUID();
  const clientIdIssuedAt = Math.floor(Date.now() / 1000);

  // Determine if this is a public or confidential client
  const tokenEndpointAuthMethod = body.token_endpoint_auth_method || "client_secret_post";
  const isPublicClient = tokenEndpointAuthMethod === "none";

  // Store client registration
  const clientData = {
    client_name: body.client_name || "MCP Client",
    redirect_uris: redirectUris,
    grant_types: body.grant_types || ["authorization_code", "refresh_token"],
    response_types: body.response_types || ["code"],
    token_endpoint_auth_method: tokenEndpointAuthMethod,
    scope: body.scope || "openid phone mcp",
    client_secret: isPublicClient ? undefined : clientSecret,
    client_id_issued_at: clientIdIssuedAt,
  };

  await env.KV.put(`client:${clientId}`, JSON.stringify(clientData));

  // Build response (don't include secret for public clients)
  const response: Record<string, any> = {
    client_id: clientId,
    client_name: clientData.client_name,
    redirect_uris: clientData.redirect_uris,
    grant_types: clientData.grant_types,
    response_types: clientData.response_types,
    token_endpoint_auth_method: clientData.token_endpoint_auth_method,
    scope: clientData.scope,
    client_id_issued_at: clientIdIssuedAt,
  };

  if (!isPublicClient) {
    response.client_secret = clientSecret;
  }

  return jsonResponse(response, 201);
}

// Show authorization form
export async function handleAuthorize(url: URL, env: Env): Promise<Response> {
  const clientId = url.searchParams.get("client_id");
  const redirectUri = url.searchParams.get("redirect_uri");
  const state = url.searchParams.get("state");
  const codeChallenge = url.searchParams.get("code_challenge");
  const codeChallengeMethod =
    url.searchParams.get("code_challenge_method") || "plain";
  const scope = url.searchParams.get("scope") || "openid phone";

  if (!clientId || !redirectUri) {
    return new Response(
      "Missing required parameters: client_id and redirect_uri",
      { status: 400 },
    );
  }

  // Store OAuth params for later use
  const sessionId = crypto.randomUUID();
  await env.KV.put(
    `session:${sessionId}`,
    JSON.stringify({
      clientId,
      redirectUri,
      state,
      codeChallenge,
      codeChallengeMethod,
      scope,
    }),
    { expirationTtl: 600 },
  );

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign In</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-gray-50 flex items-center justify-center p-4">
  <div class="w-full max-w-md">
    <div class="bg-white rounded-2xl shadow-xl border border-gray-200 p-8">
      <div class="text-center mb-8">
        <div class="inline-flex items-center justify-center w-14 h-14 bg-gray-900 rounded-xl mb-4">
          <svg class="w-7 h-7 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z"/>
          </svg>
        </div>
        <h1 class="text-2xl font-semibold text-gray-900 mb-2">Sign in</h1>
        <p class="text-gray-500">Enter your phone number to continue</p>
      </div>

      <!-- Phone Input Step -->
      <div id="phone-step">
        <form id="phone-form" class="space-y-5">
          <input type="hidden" name="session_id" value="${sessionId}">
          <div>
            <label for="phone" class="block text-sm font-medium text-gray-700 mb-1.5">Phone Number</label>
            <div class="relative">
              <div class="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                <span class="text-gray-400">+</span>
              </div>
              <input
                type="tel"
                id="phone"
                name="phone"
                placeholder="1234567890"
                class="w-full pl-8 pr-4 py-3 bg-white border border-gray-300 rounded-lg text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-gray-900 focus:border-transparent transition-all duration-150"
                required
              >
            </div>
            <p class="mt-1.5 text-xs text-gray-500">Include country code (e.g., 14155551234)</p>
          </div>
          <button
            type="submit"
            id="send-btn"
            class="w-full py-3 px-4 bg-gray-900 text-white font-medium rounded-lg hover:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-gray-900 focus:ring-offset-2 transition-all duration-150"
          >
            Send Verification Code
          </button>
        </form>
        <div id="phone-error" class="mt-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-600 text-sm hidden"></div>
      </div>

      <!-- Code Verification Step -->
      <div id="code-step" class="hidden">
        <form id="code-form" class="space-y-5">
          <input type="hidden" name="session_id" value="${sessionId}">
          <input type="hidden" id="verify-phone" name="phone">
          <div>
            <label for="code" class="block text-sm font-medium text-gray-700 mb-1.5">Verification Code</label>
            <div class="flex gap-2 justify-center">
              <input type="text" maxlength="1" class="code-input w-11 h-12 text-center text-xl font-semibold bg-white border border-gray-300 rounded-lg text-gray-900 focus:outline-none focus:ring-2 focus:ring-gray-900 focus:border-transparent transition-all duration-150" data-index="0">
              <input type="text" maxlength="1" class="code-input w-11 h-12 text-center text-xl font-semibold bg-white border border-gray-300 rounded-lg text-gray-900 focus:outline-none focus:ring-2 focus:ring-gray-900 focus:border-transparent transition-all duration-150" data-index="1">
              <input type="text" maxlength="1" class="code-input w-11 h-12 text-center text-xl font-semibold bg-white border border-gray-300 rounded-lg text-gray-900 focus:outline-none focus:ring-2 focus:ring-gray-900 focus:border-transparent transition-all duration-150" data-index="2">
              <input type="text" maxlength="1" class="code-input w-11 h-12 text-center text-xl font-semibold bg-white border border-gray-300 rounded-lg text-gray-900 focus:outline-none focus:ring-2 focus:ring-gray-900 focus:border-transparent transition-all duration-150" data-index="3">
              <input type="text" maxlength="1" class="code-input w-11 h-12 text-center text-xl font-semibold bg-white border border-gray-300 rounded-lg text-gray-900 focus:outline-none focus:ring-2 focus:ring-gray-900 focus:border-transparent transition-all duration-150" data-index="4">
              <input type="text" maxlength="1" class="code-input w-11 h-12 text-center text-xl font-semibold bg-white border border-gray-300 rounded-lg text-gray-900 focus:outline-none focus:ring-2 focus:ring-gray-900 focus:border-transparent transition-all duration-150" data-index="5">
            </div>
            <input type="hidden" id="code" name="code">
          </div>
          <button
            type="submit"
            id="verify-btn"
            class="w-full py-3 px-4 bg-gray-900 text-white font-medium rounded-lg hover:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-gray-900 focus:ring-offset-2 transition-all duration-150"
          >
            Verify & Continue
          </button>
        </form>
        <button
          id="back-btn"
          class="w-full mt-3 py-2.5 px-4 bg-white text-gray-600 font-medium rounded-lg border border-gray-300 hover:bg-gray-50 focus:outline-none transition-all duration-150"
        >
          Back
        </button>
        <div id="code-error" class="mt-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-600 text-sm hidden"></div>
      </div>

      <p class="mt-6 text-center text-xs text-gray-400">
        By continuing, you agree to receive SMS messages for verification.
      </p>
    </div>
  </div>

  <script>
    const phoneStep = document.getElementById('phone-step');
    const codeStep = document.getElementById('code-step');
    const phoneForm = document.getElementById('phone-form');
    const codeForm = document.getElementById('code-form');
    const phoneError = document.getElementById('phone-error');
    const codeError = document.getElementById('code-error');
    const codeInputs = document.querySelectorAll('.code-input');
    const codeHidden = document.getElementById('code');
    const verifyPhone = document.getElementById('verify-phone');

    // Handle code input auto-focus and paste
    codeInputs.forEach((input, index) => {
      input.addEventListener('input', (e) => {
        const value = e.target.value;
        if (value && index < 5) {
          codeInputs[index + 1].focus();
        }
        updateHiddenCode();
      });

      input.addEventListener('keydown', (e) => {
        if (e.key === 'Backspace' && !e.target.value && index > 0) {
          codeInputs[index - 1].focus();
        }
      });

      input.addEventListener('paste', (e) => {
        e.preventDefault();
        const paste = (e.clipboardData || window.clipboardData).getData('text');
        const digits = paste.replace(/\\D/g, '').slice(0, 6);
        digits.split('').forEach((digit, i) => {
          if (codeInputs[i]) codeInputs[i].value = digit;
        });
        if (digits.length > 0) {
          codeInputs[Math.min(digits.length, 5)].focus();
        }
        updateHiddenCode();
      });
    });

    function updateHiddenCode() {
      codeHidden.value = Array.from(codeInputs).map(i => i.value).join('');
    }

    phoneForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('send-btn');
      const originalText = btn.textContent;
      btn.disabled = true;
      btn.textContent = 'Sending...';
      phoneError.classList.add('hidden');

      const formData = new FormData(phoneForm);
      try {
        const response = await fetch('/send-code', {
          method: 'POST',
          body: formData
        });
        const data = await response.json();

        if (data.success) {
          verifyPhone.value = formData.get('phone');
          phoneStep.classList.add('hidden');
          codeStep.classList.remove('hidden');
          codeInputs[0].focus();
        } else {
          phoneError.textContent = data.error || 'Failed to send code';
          phoneError.classList.remove('hidden');
        }
      } catch (err) {
        phoneError.textContent = 'Network error. Please try again.';
        phoneError.classList.remove('hidden');
      }

      btn.disabled = false;
      btn.textContent = originalText;
    });

    codeForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('verify-btn');
      const originalText = btn.textContent;
      btn.disabled = true;
      btn.textContent = 'Verifying...';
      codeError.classList.add('hidden');

      const formData = new FormData(codeForm);
      try {
        const response = await fetch('/verify-code', {
          method: 'POST',
          body: formData
        });
        const data = await response.json();

        if (data.success && data.redirect_uri) {
          window.location.href = data.redirect_uri;
        } else {
          codeError.textContent = data.error || 'Invalid code';
          codeError.classList.remove('hidden');
          codeInputs.forEach(i => i.value = '');
          codeInputs[0].focus();
        }
      } catch (err) {
        codeError.textContent = 'Network error. Please try again.';
        codeError.classList.remove('hidden');
      }

      btn.disabled = false;
      btn.textContent = originalText;
    });

    document.getElementById('back-btn').addEventListener('click', () => {
      codeStep.classList.add('hidden');
      phoneStep.classList.remove('hidden');
      codeInputs.forEach(i => i.value = '');
      codeError.classList.add('hidden');
    });
  </script>
</body>
</html>`;

  return new Response(html, {
    headers: { "Content-Type": "text/html" },
  });
}

// Send SMS verification code
export async function handleSendCode(request: Request, env: Env): Promise<Response> {
  const formData = await request.formData();
  const phone = formData.get("phone") as string;
  const sessionId = formData.get("session_id") as string;

  if (!phone || !sessionId) {
    return jsonResponse(
      { success: false, error: "Missing phone or session" },
      400,
    );
  }

  // Validate phone number format (basic validation)
  const cleanPhone = phone.replace(/\D/g, "");
  if (cleanPhone.length < 10 || cleanPhone.length > 15) {
    return jsonResponse(
      { success: false, error: "Invalid phone number format" },
      400,
    );
  }

  // Check if session exists
  const sessionData = await env.KV.get(`session:${sessionId}`);
  if (!sessionData) {
    return jsonResponse(
      {
        success: false,
        error: "Session expired. Please refresh and try again.",
      },
      400,
    );
  }

  // Generate 6-digit code
  const code = String(Math.floor(100000 + Math.random() * 900000));

  // Store code with phone number (expires in 5 minutes)
  await env.KV.put(`code:${sessionId}:${cleanPhone}`, code, {
    expirationTtl: 300,
  });

  // Send SMS via Twilio
  const twilioUrl = `https://api.twilio.com/2010-04-01/Accounts/${env.TWILIO_ACCOUNT_SID}/Messages.json`;
  const auth = btoa(`${env.TWILIO_ACCOUNT_SID}:${env.TWILIO_AUTH_TOKEN}`);

  const twilioBody = new URLSearchParams({
    To: `+${cleanPhone}`,
    From: env.TWILIO_PHONE_NUMBER,
    Body: `Your verification code is: ${code}. It expires in 5 minutes.`,
  });

  try {
    const twilioResponse = await fetch(twilioUrl, {
      method: "POST",
      headers: {
        Authorization: `Basic ${auth}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: twilioBody,
    });

    if (!twilioResponse.ok) {
      const error = await twilioResponse.text();
      console.error("Twilio error:", error);
      return jsonResponse(
        {
          success: false,
          error: "Failed to send SMS. Please check your phone number.",
        },
        500,
      );
    }

    return jsonResponse({ success: true });
  } catch (error) {
    console.error("Twilio request failed:", error);
    return jsonResponse({ success: false, error: "Failed to send SMS" }, 500);
  }
}

// Verify the code and issue auth code
export async function handleVerifyCode(request: Request, env: Env): Promise<Response> {
  const formData = await request.formData();
  const phone = formData.get("phone") as string;
  const code = formData.get("code") as string;
  const sessionId = formData.get("session_id") as string;

  if (!phone || !code || !sessionId) {
    return jsonResponse(
      { success: false, error: "Missing required fields" },
      400,
    );
  }

  const cleanPhone = phone.replace(/\D/g, "");

  // Get session data
  const sessionData = await env.KV.get(`session:${sessionId}`);
  if (!sessionData) {
    return jsonResponse({ success: false, error: "Session expired" }, 400);
  }

  const session = JSON.parse(sessionData);

  // Verify code
  const storedCode = await env.KV.get(`code:${sessionId}:${cleanPhone}`);
  if (!storedCode || storedCode !== code) {
    return jsonResponse(
      { success: false, error: "Invalid or expired code" },
      400,
    );
  }

  // Delete used code
  await env.KV.delete(`code:${sessionId}:${cleanPhone}`);

  // Generate authorization code
  const authCode = crypto.randomUUID();

  // Store auth code with user info (expires in 5 minutes)
  await env.KV.put(
    `authcode:${authCode}`,
    JSON.stringify({
      phone: cleanPhone,
      clientId: session.clientId,
      redirectUri: session.redirectUri,
      codeChallenge: session.codeChallenge,
      codeChallengeMethod: session.codeChallengeMethod,
      scope: session.scope,
    }),
    { expirationTtl: 300 },
  );

  // Clean up session
  await env.KV.delete(`session:${sessionId}`);

  // Build redirect URL
  const redirectUrl = new URL(session.redirectUri);
  redirectUrl.searchParams.set("code", authCode);
  if (session.state) {
    redirectUrl.searchParams.set("state", session.state);
  }

  return jsonResponse({ success: true, redirect_uri: redirectUrl.toString() });
}

// OAuth token endpoint
export async function handleToken(request: Request, env: Env): Promise<Response> {
  const formData = await request.formData();
  const grantType = formData.get("grant_type") as string;
  const code = formData.get("code") as string;
  const redirectUri = formData.get("redirect_uri") as string;
  const codeVerifier = formData.get("code_verifier") as string;
  const refreshToken = formData.get("refresh_token") as string;

  // Handle refresh token grant
  if (grantType === "refresh_token" && refreshToken) {
    const tokenData = await env.KV.get(`refresh:${refreshToken}`);
    if (!tokenData) {
      return jsonResponse(
        { error: "invalid_grant", error_description: "Invalid refresh token" },
        400,
      );
    }

    const { phone, clientId: storedClientId, scope } = JSON.parse(tokenData);

    // Generate new tokens
    const newAccessToken = await generateJWT(
      { sub: phone, scope },
      env.JWT_SECRET,
      3600,
    );
    const newRefreshToken = crypto.randomUUID();

    // Store new refresh token
    await env.KV.put(
      `refresh:${newRefreshToken}`,
      JSON.stringify({ phone, clientId: storedClientId, scope }),
      { expirationTtl: 86400 * 30 },
    );

    // Optionally revoke old refresh token
    await env.KV.delete(`refresh:${refreshToken}`);

    return jsonResponse({
      access_token: newAccessToken,
      token_type: "Bearer",
      expires_in: 3600,
      refresh_token: newRefreshToken,
      scope,
    });
  }

  // Handle authorization code grant
  if (grantType !== "authorization_code") {
    return jsonResponse({ error: "unsupported_grant_type" }, 400);
  }

  if (!code) {
    return jsonResponse(
      { error: "invalid_request", error_description: "Missing code" },
      400,
    );
  }

  // Get auth code data
  const authCodeData = await env.KV.get(`authcode:${code}`);
  if (!authCodeData) {
    return jsonResponse(
      { error: "invalid_grant", error_description: "Invalid or expired code" },
      400,
    );
  }

  const authData = JSON.parse(authCodeData);

  // Validate redirect URI
  if (redirectUri && redirectUri !== authData.redirectUri) {
    return jsonResponse(
      { error: "invalid_grant", error_description: "Redirect URI mismatch" },
      400,
    );
  }

  // Validate PKCE if code challenge was provided
  if (authData.codeChallenge) {
    if (!codeVerifier) {
      return jsonResponse(
        {
          error: "invalid_request",
          error_description: "Missing code_verifier",
        },
        400,
      );
    }

    let computedChallenge: string;
    if (authData.codeChallengeMethod === "S256") {
      const encoder = new TextEncoder();
      const data = encoder.encode(codeVerifier);
      const hash = await crypto.subtle.digest("SHA-256", data);
      computedChallenge = base64UrlEncode(new Uint8Array(hash));
    } else {
      computedChallenge = codeVerifier;
    }

    if (computedChallenge !== authData.codeChallenge) {
      return jsonResponse(
        { error: "invalid_grant", error_description: "Invalid code_verifier" },
        400,
      );
    }
  }

  // Delete used auth code
  await env.KV.delete(`authcode:${code}`);

  // Generate tokens
  const accessToken = await generateJWT(
    { sub: authData.phone, scope: authData.scope },
    env.JWT_SECRET,
    3600,
  );
  const newRefreshToken = crypto.randomUUID();

  // Store refresh token (expires in 30 days)
  await env.KV.put(
    `refresh:${newRefreshToken}`,
    JSON.stringify({
      phone: authData.phone,
      clientId: authData.clientId,
      scope: authData.scope,
    }),
    { expirationTtl: 86400 * 30 },
  );

  return jsonResponse({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600,
    refresh_token: newRefreshToken,
    scope: authData.scope,
  });
}

// Userinfo endpoint
export async function handleUserinfo(request: Request, env: Env): Promise<Response> {
  const authHeader = request.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return jsonResponse({ error: "invalid_token" }, 401);
  }

  const token = authHeader.substring(7);

  try {
    const payload = await verifyJWT(token, env.JWT_SECRET);
    return jsonResponse({
      sub: payload.sub,
      phone_number: `+${payload.sub}`,
      phone_number_verified: true,
    });
  } catch (error) {
    return jsonResponse({ error: "invalid_token" }, 401);
  }
}

// Token revocation endpoint
export async function handleRevoke(request: Request, env: Env): Promise<Response> {
  const formData = await request.formData();
  const token = formData.get("token") as string;
  const tokenTypeHint = formData.get("token_type_hint") as string;

  if (!token) {
    return jsonResponse({ error: "invalid_request" }, 400);
  }

  // Try to revoke as refresh token
  if (!tokenTypeHint || tokenTypeHint === "refresh_token") {
    await env.KV.delete(`refresh:${token}`);
  }

  // Always return success per RFC 7009
  return new Response(null, { status: 200 });
}
