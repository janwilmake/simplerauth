// Twilio SMS OAuth Provider + MCP Server
//
// OAuth endpoints: /authorize, /send-code, /verify-code, /token, /userinfo, /register, /revoke
// OAuth metadata: /.well-known/oauth-authorization-server, /.well-known/oauth-protected-resource
// MCP endpoint: /mcp (POST)

import {
  Env,
  corsHeaders,
  withCors,
  handleMetadata,
  handleProtectedResourceMetadata,
  handleRegister,
  handleAuthorize,
  handleSendCode,
  handleVerifyCode,
  handleToken,
  handleUserinfo,
  handleRevoke,
} from "./oauth-provider";

import { handleMcp } from "./mcp";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // Handle CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    try {
      // OAuth metadata endpoint
      if (path === "/.well-known/oauth-authorization-server") {
        return withCors(handleMetadata(url));
      }

      // Protected resource metadata for MCP
      if (path === "/.well-known/oauth-protected-resource") {
        return withCors(handleProtectedResourceMetadata(url));
      }

      // Dynamic Client Registration (RFC 7591)
      if (path === "/register" && request.method === "POST") {
        return withCors(await handleRegister(request, env));
      }

      // Authorization endpoint - show login form
      if (path === "/authorize" && request.method === "GET") {
        return withCors(await handleAuthorize(url, env));
      }

      // Send verification code
      if (path === "/send-code" && request.method === "POST") {
        return withCors(await handleSendCode(request, env));
      }

      // Verify code
      if (path === "/verify-code" && request.method === "POST") {
        return withCors(await handleVerifyCode(request, env));
      }

      // Token endpoint
      if (path === "/token" && request.method === "POST") {
        return withCors(await handleToken(request, env));
      }

      // Userinfo endpoint
      if (path === "/userinfo" && request.method === "GET") {
        return withCors(await handleUserinfo(request, env));
      }

      // Token revocation
      if (path === "/revoke" && request.method === "POST") {
        return withCors(await handleRevoke(request, env));
      }

      // MCP endpoint
      if (path === "/mcp" && request.method === "POST") {
        return withCors(await handleMcp(request, env));
      }

      return withCors(new Response("Not Found", { status: 404 }));
    } catch (error) {
      console.error("Error:", error);
      return withCors(new Response("Internal Server Error", { status: 500 }));
    }
  },
};
