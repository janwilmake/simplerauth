Facilitates simple redirect from `/callback` to whitelisted hostnames, allowing to circumvent the X OAuth client callback-url limitation of max 10.

Usage:

- deploy this on your own cloudflare
- edit the `wrangler.json`
  - `ALLOWED_HOSTNAMES`: which hostnames you trust to redirect to
  - `routes`: your preferred route
- now you can redirect to any of these hostnames by using `redirect_to`, e.g. `https://redirect.yourdomain.com/callback?redirect_to=https://yourworkerthatneedsauth.com/callback`
