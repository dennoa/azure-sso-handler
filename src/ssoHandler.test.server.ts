import express from 'express';
import cookieParser from 'cookie-parser';
import { AzureSSOHandler } from './ssoHandler';

const app = express();
app.use(cookieParser());

const sso = new AzureSSOHandler({
  clientId: process.env.AZURE_CLIENT_ID || 'client-id',
  clientSecret: process.env.AZURE_CLIENT_SECRET || 'client-secret',
  tenantId: process.env.AZURE_TENANT_ID || 'tenant-id',
  scope: process.env.AZURE_SCOPE || 'openid offline_access',
  redirectUri: process.env.AZURE_REDIRECT_URI || 'http://localhost:3000/callback',
  cookieNames: {
    accessToken: process.env.COOKIE_NAME_ACCESS_TOKEN || 'access_token',
    idToken: process.env.COOKIE_NAME_ID_TOKEN || 'id_token',
    refreshToken: process.env.COOKIE_NAME_REFRESH_TOKEN || 'refresh_token',
  },
});

app.get('/login', (req, res) => sso.login(req, res));
app.get('/callback', (req, res) => sso.handleAzureCallback(req, res));
app.get('/refresh', (req, res) => sso.refresh(req, res));
app.get('/logout', (req, res) => sso.logout(req, res));
app.get('/validate', (req, res) => sso.validate(req, res));
app.get('/', (req, res) => res.sendFile('ssoHandler.test.html', { root: __dirname }));

app.listen(3000, () => console.log('Server running on http://localhost:3000'));

// http://localhost:3000/login?return_url=http://localhost:3000/validate
// http://localhost:3000/validate
// http://localhost:3000/refresh
// http://localhost:3000/logout?return_url=http://localhost:3000/validate
