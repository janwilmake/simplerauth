# GitHub OAuth CLI Template

[![janwilmake/github-oauth-cli context](https://badge.forgithub.com/janwilmake/github-oauth-cli)](https://uithub.com/janwilmake/github-oauth-cli) [![](https://b.lmpify.com/Example%20Pied%20Piper%20CLI)](https://lmpify.com/httpsuithubcomj-3z7y8q0)

Example on how to set up oauth with github in a cli

How I made it:

- [![](https://b.lmpify.com/Token%20Exchange%20Proxy)](https://www.lmpify.com/httpsuuithubcom-ow5mjz0)
- [![](https://b.lmpify.com/OAuth%20cli)](https://www.lmpify.com/httpsuithubcomj-m8tfk00)

How to set it up:

1. Create a new oauth app via https://github.com/settings/applications/new: regular flow - not device flow, callback to http://127.0.0.1:9001, and gather `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`
2. Deploy your worker and ensure to hardcode the worker URL and GITHUB_CLIENT_ID in the `cli.js` as well.
3. Make it a npm package as you'd normally do and publish to npm.
4. Profit! Change your scope as desired.
