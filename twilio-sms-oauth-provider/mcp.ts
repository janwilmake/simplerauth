// MCP Server - Twilio SMS Tool
// Endpoint: POST /mcp
// Provides send_sms tool for authenticated users

import { Env, jsonResponse, verifyJWT } from "./oauth-provider";

export async function handleMcp(request: Request, env: Env): Promise<Response> {
  // Verify authorization
  const authHeader = request.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return jsonResponse(
      {
        jsonrpc: "2.0",
        error: { code: -32001, message: "Unauthorized" },
        id: null,
      },
      401,
    );
  }

  const token = authHeader.substring(7);
  let phone;
  try {
    phone = (await verifyJWT(token, env.JWT_SECRET)).sub;
  } catch {
    return jsonResponse(
      {
        jsonrpc: "2.0",
        error: { code: -32001, message: "Invalid token" },
        id: null,
      },
      401,
    );
  }

  // Parse MCP request
  let body: {
    jsonrpc: string;
    method: string;
    params?: any;
    id: string | number;
  };
  try {
    body = await request.json();
  } catch {
    return jsonResponse(
      {
        jsonrpc: "2.0",
        error: { code: -32700, message: "Parse error" },
        id: null,
      },
      400,
    );
  }

  const { method, params, id } = body;

  // Handle MCP methods
  switch (method) {
    case "initialize":
      return jsonResponse({
        jsonrpc: "2.0",
        result: {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: { name: "twilio-sms-oauth", version: "1.0.0" },
        },
        id,
      });

    case "notifications/initialized":
      return jsonResponse({ jsonrpc: "2.0", result: {}, id });

    case "tools/list":
      return jsonResponse({
        jsonrpc: "2.0",
        result: {
          tools: [
            {
              name: "send_sms",
              description: "Send an SMS message to your phone number",
              inputSchema: {
                type: "object",
                properties: {
                  message: {
                    type: "string",
                    description: "The message to send",
                  },
                },
                required: ["to", "message"],
              },
            },
          ],
        },
        id,
      });

    case "tools/call":
      if (params?.name === "send_sms") {
        const { message } = params.arguments || {};

        if (!message) {
          return jsonResponse({
            jsonrpc: "2.0",
            result: {
              content: [
                {
                  type: "text",
                  text: "Error: 'message' is required",
                },
              ],
              isError: true,
            },
            id,
          });
        }

        // Send SMS via Twilio
        const twilioUrl = `https://api.twilio.com/2010-04-01/Accounts/${env.TWILIO_ACCOUNT_SID}/Messages.json`;
        const auth = btoa(`${env.TWILIO_ACCOUNT_SID}:${env.TWILIO_AUTH_TOKEN}`);

        const twilioBody = new URLSearchParams({
          To: phone.startsWith("+") ? phone : `+${phone}`,
          From: env.TWILIO_PHONE_NUMBER,
          Body: message,
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
            return jsonResponse({
              jsonrpc: "2.0",
              result: {
                content: [
                  { type: "text", text: `Failed to send SMS: ${error}` },
                ],
                isError: true,
              },
              id,
            });
          }

          const result = (await twilioResponse.json()) as { sid: string };
          return jsonResponse({
            jsonrpc: "2.0",
            result: {
              content: [
                {
                  type: "text",
                  text: `SMS sent successfully. Message SID: ${result.sid}`,
                },
              ],
            },
            id,
          });
        } catch (err) {
          return jsonResponse({
            jsonrpc: "2.0",
            result: {
              content: [{ type: "text", text: `Error sending SMS: ${err}` }],
              isError: true,
            },
            id,
          });
        }
      }

      return jsonResponse({
        jsonrpc: "2.0",
        error: { code: -32601, message: `Unknown tool: ${params?.name}` },
        id,
      });

    default:
      return jsonResponse({
        jsonrpc: "2.0",
        error: { code: -32601, message: `Method not found: ${method}` },
        id,
      });
  }
}
