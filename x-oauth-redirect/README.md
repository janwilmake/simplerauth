Facilitates simple redirect from `/callback` to whitelisted hostnames, allowing to circumvent the X OAuth client callback-url limitation of max 10.

Usage:

- deploy this on your own cloudflare
- edit the `wrangler.json` -> `ALLOWED_HOSTNAMES`
