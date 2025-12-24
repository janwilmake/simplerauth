https://uithub.com/janwilmake/uitx/tree/main/forgithub.oauthproxy?lines=false

make a node.js file cli.js without dependencies that:

- looks in global location .uitx for access_token
- if available, uses GitHub api to get user info with that
- if available but 401 returned, removes access_token from global
- if not available, or if 401 returned, opens GitHub https://github.com/login/oauth/authorize?client_id=${env.GITHUB_CLIENT_ID}&redirect_uri=http://127.0.0.1:9001/callback&scope=user:email&state=${randomState} with clientId hardcoded to Ov23liNRLqKVzCdfAhWs
- when opening that, also spawns a temporary http server at 9001 that listens for the GET /callback endpoint
- the GET /callback will confirm the state is correct, call the proxy wit the code and retrieve the access token, after which the temp http server gets closed and the access_token gets stored in the global location.

NB: use regular "fetch" to do the api calls, but use http to spawn the temporary server

Result: https://www.lmpify.com/httpsuithubcomj-m8tfk00
