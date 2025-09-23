// Azure SSO Handler main class
// Use generic types for request/response to avoid Node.js dependency
const msal = require('@azure/msal-node');
const jwt = require('jsonwebtoken');
const jwksRsa = require('jwks-rsa');

export interface AzureSSOConfig {
  clientId: string;
  clientSecret: string;
  tenantId: string;
  scope: string;
  redirectUri: string;
  shouldLogoutFromAzure?: boolean;
  cookieNames?: {
    accessToken: string;
    idToken: string;
    refreshToken: string;
  }
}

export interface TokenValidationResult {
  isValidAccessToken: boolean;
  isValidIdToken: boolean;
  decodedAccessToken?: any;
  decodedIdToken?: any;
}

export const defaultCookieNames = {
  accessToken: 'access_token',
  idToken: 'id_token',
  refreshToken: 'refresh_token',
};

export class AzureSSOHandler {
  private config: AzureSSOConfig;
  private jwksClient: any;

  constructor(config: AzureSSOConfig) {
    this.config = config;
    const jwksUri = `https://login.microsoftonline.com/${this.config.tenantId}/discovery/v2.0/keys`;
    this.jwksClient = jwksRsa({ jwksUri });
  }

  // Initiate login flow by redirecting to Azure
  public login(req: any, res: any): void {
    const authorizeUrl = this._buildAuthorizeUrl(req);
    this._redirect(res, authorizeUrl);
  }

  private _redirect(res: any, url: string) {
    if (res.redirect) {
      res.redirect(url);
    } else if (res.writeHead && res.end) {
      res.writeHead(302, { Location: url });
      res.end();
    } else {
      throw new Error('Response object does not support redirection');
    }
  }

  private _buildAuthorizeUrl(req: any): string {
    const state = req.query?.return_url || '/';
    return (
      `https://login.microsoftonline.com/${this.config.tenantId}/oauth2/v2.0/authorize?` +
      `client_id=${encodeURIComponent(this.config.clientId)}` +
      `&response_type=code` +
      `&redirect_uri=${encodeURIComponent(this.config.redirectUri)}` +
      `&response_mode=query` +
      `&scope=${encodeURIComponent(this.config.scope)}` +
      `&state=${encodeURIComponent(state)}`
    );
  }

  // Handle callback from Azure to exchange code for tokens using MSAL
  public async handleAzureCallback(req: any, res: any): Promise<void> {
    const code = req.query?.code;
    if (!code) {
      res.status?.(400)?.send?.('Missing authorization code');
      return;
    }
    try {
      const cca = this._getCca();
      const response = await cca.acquireTokenByCode({
        code,
        scopes: this.config.scope.split(','),
        redirectUri: this.config.redirectUri,
      });
      if (res.cookie) {
        this._setCookies(response, res);
      }
      const returnUrl = req.query?.state || '/';
      this._redirect(res, returnUrl);
    } catch (err: any) {
      if (res.status && res.send) {
        res.status(401).send('Token exchange failed: ' + err.message);
      } else {
        throw err;
      }
    }
  }

  private _getCca() {
    return new msal.ConfidentialClientApplication({
      auth: {
        clientId: this.config.clientId,
        authority: `https://login.microsoftonline.com/${this.config.tenantId}`,
        clientSecret: this.config.clientSecret,
      },
    });
  }

  private _setCookies(response: any, res: any) {
    const expires = new Date(Date.now() + (response.expires_in || 3600) * 1000);
    const opts = { httpOnly: true, expires, path: '/', secure: true, sameSite: 'none' };
    const cookieNames = this.config.cookieNames || defaultCookieNames;
    if (response.accessToken) {
      res.cookie(cookieNames.accessToken, response.accessToken, opts);
    }
    if (response.idToken) {
      res.cookie(cookieNames.idToken, response.idToken, opts);
    }
    if (response.refreshToken) {
      res.cookie(cookieNames.refreshToken, response.refreshToken, opts);
    }
  }

  // Refresh tokens as required
  public async refresh(req: any, res: any): Promise<void> {
    const cookieNames = this.config.cookieNames || defaultCookieNames;
    const refreshToken = req.cookies?.[cookieNames.refreshToken];
    if (!refreshToken) {
      res.status?.(400)?.send?.('Missing refresh token');
      return;
    }
    try {
      const cca = this._getCca();
      const response = await cca.acquireTokenByRefreshToken({
        refreshToken,
        scopes: this.config.scope.split(','),
      });
      if (res.cookie) {
        this._setCookies(response, res);
      }
      res.status?.(200)?.send?.('Tokens refreshed');
    } catch (err: any) {
      if (res.status && res.send) {
        res.status(401).send('Token refresh failed: ' + err.message);
      } else {
        throw err;
      }
    }
  }

  // Logout by clearing cookies and optionally redirecting to Azure logout
  public logout(req: any, res: any): void {
    if (res.clearCookie) {
      const opts = { path: '/' };
      const cookieNames = this.config.cookieNames || defaultCookieNames;
      res.clearCookie(cookieNames.accessToken, opts);
      res.clearCookie(cookieNames.idToken, opts);
      res.clearCookie(cookieNames.refreshToken, opts);
    }

    const returnUrl = req.query?.return_url || '/';
    const logoutUrl = this.config.shouldLogoutFromAzure
      ? `https://login.microsoftonline.com/${this.config.tenantId}/oauth2/v2.0/logout?` +
        `post_logout_redirect_uri=${encodeURIComponent(returnUrl)}`
      : returnUrl;
    this._redirect(res, logoutUrl);
  }

  public async validate(req: any, res: any, next?: any): Promise<void> {
    const cookieNames = this.config.cookieNames || defaultCookieNames;
    const accessToken = req.cookies?.[cookieNames.accessToken];
    const idToken = req.cookies?.[cookieNames.idToken];
    const result = await this.validateTokens(accessToken, idToken);
    if (result.isValidAccessToken || result.isValidIdToken) {
      if (next) {
        req[cookieNames.accessToken] = result.decodedAccessToken;
        req[cookieNames.idToken] = result.decodedIdToken;
        return next();
      }
      res.status?.(200)?.json?.(result);
    } else {
      res.status?.(401)?.json?.(result);
    }
  }
  
  // Validate both access_token and id_token using jwks-rsa and jsonwebtoken
  public async validateTokens(accessToken: string, idToken: string): Promise<TokenValidationResult> {
    const accessTokenResult = await this._verifyToken(accessToken);
    const idTokenResult = await this._verifyToken(idToken);
    const isValidAccessToken = accessTokenResult.valid;
    const decodedAccessToken = accessTokenResult.decoded;
    const isValidIdToken = idTokenResult.valid;
    const decodedIdToken = idTokenResult.decoded;
    return { isValidAccessToken, decodedAccessToken, isValidIdToken, decodedIdToken };
  }

  private async _verifyToken(token: string): Promise<any> {
    let valid = false;
    if (!token) return { valid };
    const decoded = jwt.decode(token, { complete: true });
    if (decoded?.header?.kid) {
      try {
        const key = await this.jwksClient.getSigningKey(decoded.header.kid);
        const publicKey = key.getPublicKey();
        valid = !!jwt.verify(token, publicKey);
      } catch {
        // Nothing to do here
      }
    }
    return { valid, decoded };
  }
}
