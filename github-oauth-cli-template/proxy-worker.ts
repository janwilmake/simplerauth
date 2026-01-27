export interface Env {
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Enable CORS for pre-flight requests
    if (request.method === "OPTIONS") {
      return handleCORS();
    }

    // Only handle POST requests to /login/oauth/access_token endpoint
    const url = new URL(request.url);
    if (
      request.method === "POST" &&
      url.pathname === "/login/oauth/access_token"
    ) {
      return handleTokenExchange(request, env);
    }

    // Return 404 for any other routes
    return new Response("Not Found", { status: 404 });
  },
};

async function handleTokenExchange(
  request: Request,
  env: Env,
): Promise<Response> {
  try {
    // Parse the request body
    let requestBody: any;
    const contentType = request.headers.get("Content-Type");

    if (contentType?.includes("application/json")) {
      requestBody = await request.json();
    } else if (contentType?.includes("application/x-www-form-urlencoded")) {
      const formData = await request.formData();
      requestBody = Object.fromEntries(formData.entries());
    } else {
      return new Response("Unsupported content type", { status: 415 });
    }

    // Ensure code is provided
    if (!requestBody.code) {
      return new Response("Missing required parameter: code", {
        status: 400,
        headers: getCORSHeaders(),
      });
    }

    // Create the request body for GitHub
    const githubRequestBody = {
      client_id: env.GITHUB_CLIENT_ID,
      client_secret: env.GITHUB_CLIENT_SECRET,
      code: requestBody.code,
      // Pass through optional parameters if provided
      redirect_uri: requestBody.redirect_uri,
      state: requestBody.state,
    };

    // Exchange code for token with GitHub
    const tokenResponse = await fetch(
      "https://github.com/login/oauth/access_token",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          "User-Agent": "CloudflareWorker",
        },
        body: JSON.stringify(githubRequestBody),
      },
    );

    // Return GitHub's response
    const githubData = await tokenResponse.json();

    // Create response with appropriate headers
    return new Response(JSON.stringify(githubData), {
      status: tokenResponse.status,
      headers: {
        "Content-Type": "application/json",
        ...getCORSHeaders(),
      },
    });
  } catch (error) {
    console.error("Error in token exchange:", error);
    return new Response("Internal Server Error", {
      status: 500,
      headers: getCORSHeaders(),
    });
  }
}

function handleCORS(): Response {
  return new Response(null, {
    status: 204,
    headers: getCORSHeaders(),
  });
}

function getCORSHeaders(): HeadersInit {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
  };
}
