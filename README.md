[Thread](https://x.com/janwilmake/status/2003837468122947702)

| Template                                                              | Tokens                                                                                       | Demo                                       | Description                                                                              |
| --------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | ------------------------------------------ | ---------------------------------------------------------------------------------------- |
| [cloudflare-oauth-provider](cloudflare-oauth-provider/)               | [17.7k](https://uithub.com/janwilmake/simplerauth/tree/main/cloudflare-oauth-provider)       | [open](https://cloudflare.simplerauth.com) | Login with Cloudflare - MCP-compatible OAuth provider for Cloudflare ecosystem           |
| [github-oauth-cli-template](github-oauth-cli-template/)               | [2.5k](https://uithub.com/janwilmake/simplerauth/tree/main/github-oauth-cli-template)        | -                                          | Template for setting up GitHub OAuth in a CLI application                                |
| [github-oauth-client-provider](github-oauth-client-provider/)         | [7.9k](https://uithub.com/janwilmake/simplerauth/tree/main/github-oauth-client-provider)     | -                                          | GitHub OAuth provider using hostname as client_id - no client registration needed        |
| [github-oauth-middleware](github-oauth-middleware/)                   | [1.8k](https://uithub.com/janwilmake/simplerauth/tree/main/github-oauth-middleware)          | -                                          | Simple GitHub OAuth middleware for Cloudflare Workers                                    |
| [github-oauth-provider](github-oauth-provider/)                       | [9.5k](https://uithub.com/janwilmake/simplerauth/tree/main/github-oauth-provider)            | -                                          | GitHub OAuth Provider proxy following x-oauth-provider principles                        |
| [openrouter-oauth-provider](openrouter-oauth-provider/)               | [4.5k](https://uithub.com/janwilmake/simplerauth/tree/main/openrouter-oauth-provider)        | [open](https://openrouter.simplerauth.com) | MCP-compliant OAuth provider that proxies to OpenRouter for API keys with budget control |
| [parallel-oauth-provider](parallel-oauth-provider/)                   | [13.3k](https://uithub.com/janwilmake/simplerauth/tree/main/parallel-oauth-provider)         | [open](https://oauth.parallel.ai)          | Stateless OAuth provider for Parallel.ai API key sharing                                 |
| [simplerauth-client](simplerauth-client/)                             | [5.8k](https://uithub.com/janwilmake/simplerauth/tree/main/simplerauth-client)               | [open](https://client.simplerauth.com)     | Zero-config OAuth client middleware for Cloudflare Workers                               |
| [simplerauth-hn-oauth-client-demo](simplerauth-hn-oauth-client-demo/) | [1.4k](https://uithub.com/janwilmake/simplerauth/tree/main/simplerauth-hn-oauth-client-demo) | -                                          | Demo for HackerNews OAuth (rate-limited in production)                                   |
| [simplerauth](simplerauth/)                                           | [1.0k](https://uithub.com/janwilmake/simplerauth/tree/main/simplerauth)                      | [open](https://simplerauth.com)            | Landing page for SimplerAuth                                                             |
| [x-dorm-template](x-dorm-template/)                                   | [3.6k](https://uithub.com/janwilmake/simplerauth/tree/main/x-dorm-template)                  | -                                          | Template for X OAuth + DORM user management with Outerbase                               |
| [x-oauth-middleware](x-oauth-middleware/)                             | [5.8k](https://uithub.com/janwilmake/simplerauth/tree/main/x-oauth-middleware)               | -                                          | X OAuth middleware template from first principles                                        |
| [x-oauth-provider](x-oauth-provider/)                                 | [12.6k](https://uithub.com/janwilmake/simplerauth/tree/main/x-oauth-provider)                | [open](https://login.wilmake.com)          | X OAuth Provider using hostname as client_id - unlimited X authed apps                   |

# Goals

- Go against popular advice to abstract away auth using a prominent auth library
- Be MCP compatible so you can use this in minimal MCP servers
- To be used as code snippet as well as libraries

# Context Used

- [MCP Authorization Spec](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization.md) (8.3k tokens)
- [MCP Security best practices](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices.md) (4.7k tokens)
- OAuth 2.0 Authorization Server Metadata ([RFC8414](https://www.rfc-editor.org/rfc/rfc8414.txt)): `/.well-known/oauth-authorization-server` (10.8k tokens)
- OAuth 2.0 Protected Resource Metadata ([RFC9728](https://www.rfc-editor.org/rfc/rfc9728.txt)): `/.well-known/oauth-protected-resource` (12k tokens)
