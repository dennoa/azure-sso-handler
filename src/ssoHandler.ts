import msal from '@azure/msal-node';
import type { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import jwksRsa from 'jwks-rsa';

interface AzureSSOCookieNames {
  accessToken: string;
  idToken: string;
  refreshToken: string;
}

interface AzureSSOCookieOpts {
  path?: string;
  samesite?: string;
  expiresInSecs?: number;
}

export interface AzureSSOConfig {
  clientId: string;
  clientSecret: string;
  tenantId: string;
  scope: string;
  redirectUri: string;
  cookieNames?: AzureSSOCookieNames;
  cookieOpts?: AzureSSOCookieOpts;
}

export interface TokenValidationResult {
  isValidAccessToken: boolean;
  isValidIdToken: boolean;
  decodedAccessToken?: any;
  decodedIdToken?: any;
}

export const defaultCookieNames: AzureSSOCookieNames = {
  accessToken: 'access_token',
  idToken: 'id_token',
  refreshToken: 'refresh_token',
};

export const defaultCookieOpts: AzureSSOCookieOpts = {
  path: '/',
  samesite: 'strict',
  expiresInSecs: 3600,
};

export class AzureSSOHandler {
  private config: AzureSSOConfig;
  private cookieOpts: AzureSSOCookieOpts;
  private jwksClient: any;

  constructor(config: AzureSSOConfig) {
    this.config = config;
    this.cookieOpts = {
      path: config.cookieOpts?.path ?? defaultCookieOpts.path,
      samesite: config.cookieOpts?.samesite ?? defaultCookieOpts.samesite,
      expiresInSecs: config.cookieOpts?.expiresInSecs ?? defaultCookieOpts.expiresInSecs,
    };
    const jwksUri = `https://login.microsoftonline.com/${this.config.tenantId}/discovery/v2.0/keys`;
    this.jwksClient = jwksRsa({ jwksUri });
  }

  // Initiate login flow by redirecting to Azure
  // Use generic types for request/response to avoid specific dependencies
  public login(req: Request, res: Response): void {
    const authorizeUrl = this._buildAuthorizeUrl(req.query.return_url as string || '/', 'none');
    res.redirect(authorizeUrl);
  }

  private _buildAuthorizeUrl(state: string, prompt: string): string {
    return (
      `https://login.microsoftonline.com/${this.config.tenantId}/oauth2/v2.0/authorize?` +
      `client_id=${encodeURIComponent(this.config.clientId)}` +
      `&response_type=code` +
      `&redirect_uri=${encodeURIComponent(this.config.redirectUri)}` +
      `&response_mode=query` +
      `&scope=${encodeURIComponent(this.config.scope)}` +
      `&state=${encodeURIComponent(state)}` +
      `&prompt=${prompt}`
    );
  }

  // Handle callback from Azure to exchange code for tokens using MSAL
  public async handleAzureCallback(req: Request, res: Response): Promise<void> {
    const error = req.query.error as string;
    if (error) {
      this._handleAzureCallbackError(error, req.query.state as string || '/', res);
      return;
    }
    const code = req.query.code as string;
    if (!code) {
      res.status(400).json({ error: 'Missing authorization code' });
      return;
    }
    try {
      const cca = this._getCca();
      const response = await cca.acquireTokenByCode({
        code,
        scopes: this.config.scope.split(','),
        redirectUri: this.config.redirectUri,
      });
      this._setCookies(response, res);
      res.redirect(req.query.state as string || '/');
    } catch (err: any) {
      res.status(401).send(`Token exchange failed: ${err.message}`);
    }
  }

  private _handleAzureCallbackError(error: string, state: string, res: any) {
    if (error === 'login_required' || error === 'interaction_required' || error === 'consent_required') {
      res.redirect(this._buildAuthorizeUrl(state, 'login'));
      return;
    }
    res.status(401).send(`Token exchange failed: ${error}`);
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
    const expiresInSecs = Math.min(response.expires_in ?? this.cookieOpts.expiresInSecs, this.cookieOpts.expiresInSecs!);
    const expires = new Date(Date.now() + expiresInSecs * 1000);
    const opts = { httpOnly: true, expires, path: this.cookieOpts.path, secure: true, sameSite: this.cookieOpts.samesite };
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
    const refreshToken = req.cookies[cookieNames.refreshToken];
    if (!refreshToken) {
      res.status(400).json({ error: 'Missing refresh token' });
      return;
    }
    try {
      const cca = this._getCca();
      const response = await cca.acquireTokenByRefreshToken({
        refreshToken,
        scopes: this.config.scope.split(','),
      });
      this._setCookies(response, res);
      res.status(204).send();
    } catch (err: any) {
      res.status(401).json({ error: `Token refresh failed: ${err.message}` });
    }
  }

  // Logout by clearing cookies and optionally redirecting to Azure logout
  public logout(req: any, res: any): void {
    const opts = { path: this.cookieOpts.path };
    const cookieNames = this.config.cookieNames || defaultCookieNames;
    res.clearCookie(cookieNames.accessToken, opts);
    res.clearCookie(cookieNames.idToken, opts);
    res.clearCookie(cookieNames.refreshToken, opts);
    if (req.query.return_url) {
      res.redirect(req.query.return_url);
    } else {
      res.status(204).send();
    }
  }

  public async validate(req: any, res: any, next?: any): Promise<void> {
    const cookieNames = this.config.cookieNames || defaultCookieNames;
    const accessToken = req.cookies[cookieNames.accessToken];
    const idToken = req.cookies[cookieNames.idToken];
    const result = await this.validateTokens(accessToken, idToken);
    if (result.isValidAccessToken || result.isValidIdToken) {
      if (next) {
        req[cookieNames.accessToken] = result.decodedAccessToken;
        req[cookieNames.idToken] = result.decodedIdToken;
        return next();
      }
      res.status(200).json(result);
    } else {
      res.status(401).json(result);
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
