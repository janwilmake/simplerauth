// this package can either be copied or installed via 'npm i smootherauth-github'
import { handleOAuth, getCurrentUser, type Env } from './oauth-middleware';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Handle OAuth routes first
    const oauthResponse = await handleOAuth(request, env, "user:email");
    if (oauthResponse) {
      return oauthResponse;
    }
    
    // Example protected route
    const url = new URL(request.url);
    if (url.pathname === '/protected') {
      const user = getCurrentUser(request);
      if (!user) {
        return new Response(null, {status:302,headers:{Location:'/login?redirect_to=' + encodeURIComponent(url.pathname)}});
      }
      
      return new Response(`Hello ${user.login}! You are authenticated.`, {
        headers: { 'Content-Type': 'text/plain' }
      });
    }
    
    // Default route
    if (url.pathname === '/') {
      const user = getCurrentUser(request);
      const html = user 
        ? `<h1>Welcome ${user.login}!</h1><a href="/logout">Logout</a> | <a href="/protected">Protected Page</a>`
        : `<h1>Not logged in</h1><a href="/login">Login with GitHub</a>`;
      
      return new Response(html, {
        headers: { 'Content-Type': 'text/html' }
      });
    }
    
    return new Response('Not Found', { status: 404 });
  },
};