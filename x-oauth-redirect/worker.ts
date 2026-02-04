export interface Env {
  ALLOWED_HOSTNAMES: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Parse allowed hostnames from comma-separated string
    const allowedHostnames = env.ALLOWED_HOSTNAMES.split(",").map((h) =>
      h.trim(),
    );

    // Get the target URL from query parameter
    const redirectTo = url.searchParams.get("redirect_to");

    if (!redirectTo) {
      return new Response("Missing redirect_to parameter", { status: 400 });
    }

    // Parse and validate the redirect URL
    let targetUrl: URL;
    try {
      targetUrl = new URL(redirectTo);
    } catch (e) {
      return new Response("Invalid redirect_to URL", { status: 400 });
    }

    // Validate the target hostname is in the allowed list
    if (
      !allowedHostnames.find((hostname) => {
        const chunks = targetUrl.hostname.split(".").reverse();

        if (targetUrl.hostname === hostname) {
          // localhost
          return true;
        }
        let possible: string[] = [];

        // something.wilmake.workers.dev
        chunks.forEach((_, index, array) => {
          if (index < 2) {
            // need at least 1 complete chunks
            return;
          }
          const hostname = array.slice(0, index).reverse().join(".");
          possible.push(hostname);
        });

        return possible.includes(hostname);
      })
    ) {
      console.log({ hostname: targetUrl.hostname, allowedHostnames });
      return new Response("Unauthorized redirect target", { status: 403 });
    }

    // Extract all query parameters except redirect_to
    url.searchParams.forEach((value, key) => {
      if (key !== "redirect_to") {
        targetUrl.searchParams.append(key, value);
      }
    });

    // Redirect to the target with all OAuth callback parameters
    return Response.redirect(targetUrl.toString(), 302);
  },
};
