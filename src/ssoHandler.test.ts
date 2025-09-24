import type { Request, Response } from 'express';
import jwt from 'jsonwebtoken';

const acquireTokenByCode = jest.fn();
const acquireTokenByRefreshToken = jest.fn();

jest.mock('@azure/msal-node', () => {
  return {
    ConfidentialClientApplication: jest.fn().mockImplementation(() => ({
      acquireTokenByCode,
      acquireTokenByRefreshToken,
    })),
  };
});

const getSigningKey = jest.fn();

jest.mock('jwks-rsa', () => {
  return jest.fn().mockImplementation(() => ({ getSigningKey }));
});

// Import after the mock to ensure it's used
import { AzureSSOHandler, AzureSSOConfig, TokenValidationResult, defaultCookieNames } from './ssoHandler';

describe('AzureSSOHandler', () => {
  const config: AzureSSOConfig = {
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    tenantId: 'test-tenant-id',
    scope: 'openid profile email',
    redirectUri: 'http://localhost/callback',
    cookieNames: defaultCookieNames,
  };

  let handler: AzureSSOHandler;
  let req: Request;
  let res: Response;
  beforeEach(() => {
    handler = new AzureSSOHandler(config);
    req = { query: {}, cookies: {} } as Request;
    res = { redirect: jest.fn(), status: jest.fn().mockReturnThis(), send: jest.fn(), json: jest.fn(), cookie: jest.fn(), clearCookie: jest.fn() } as unknown as Response;
  });

  it('should build the correct authorize URL on initial login', () => {
    req.query.return_url = '/dashboard';
    handler.login(req, res);
    expect(res.redirect).toHaveBeenCalled();
    const url = (res.redirect as jest.Mock).mock.calls[0][0];
    expect(url).toContain(config.tenantId);
    expect(url).toContain(`client_id=${config.clientId}`);
    expect(url).toContain(`state=${encodeURIComponent('/dashboard')}`);
    expect(url).toContain('prompt=none');
  });

  it('should handle a successful login callback', async () => {
    req.query.code = 'auth-code';
    req.query.state = '/dashboard';
    acquireTokenByCode.mockResolvedValue({
      accessToken: 'at',
      idToken: 'it',
      refreshToken: 'rt',
      expires_in: 3600,
    });
    await handler.handleAzureCallback(req, res);
    expect(res.cookie).toHaveBeenCalledWith('access_token', 'at', expect.any(Object));
    expect(res.cookie).toHaveBeenCalledWith('id_token', 'it', expect.any(Object));
    expect(res.cookie).toHaveBeenCalledWith('refresh_token', 'rt', expect.any(Object));
    expect(res.redirect).toHaveBeenCalledWith('/dashboard');
  });

  ['login_required', 'interaction_required', 'consent_required'].forEach((error) => {
    it(`should handle a login callback indicating ${error}`, async () => {
      req.query.error = error;
      req.query.state = '/dashboard';
      await handler.handleAzureCallback(req, res);
      expect(res.cookie).not.toHaveBeenCalled();
      expect(res.redirect).toHaveBeenCalled();
      const url = (res.redirect as jest.Mock).mock.calls[0][0];
      expect(url).toContain(config.tenantId);
      expect(url).toContain(`client_id=${config.clientId}`);
      expect(url).toContain(`state=${encodeURIComponent('/dashboard')}`);
      expect(url).toContain('prompt=login');
    });
  });

  it('should handle a failed token exchange', async () => {
    req.query.code = 'auth-code';
    req.query.state = '/dashboard';
    acquireTokenByCode.mockRejectedValue(new Error('Your token is garbage'));
    await handler.handleAzureCallback(req, res);
    expect(res.cookie).not.toHaveBeenCalled();
    expect(res.redirect).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.send).toHaveBeenCalledWith('Token exchange failed: Your token is garbage');
  });

  it('should refresh the tokens', async () => {
    req.cookies['refresh_token'] = 'rt';
    acquireTokenByRefreshToken.mockResolvedValue({
      accessToken: 'at',
      idToken: 'it',
      refreshToken: 'rt',
      expires_in: 3600,
    });
    await handler.refresh(req, res);
    expect(res.cookie).toHaveBeenCalledWith('access_token', 'at', expect.any(Object));
    expect(res.cookie).toHaveBeenCalledWith('id_token', 'it', expect.any(Object));
    expect(res.cookie).toHaveBeenCalledWith('refresh_token', 'rt', expect.any(Object));
    expect(res.status).toHaveBeenCalledWith(204);
  });

  it('should error if no refresh token provided', async () => {
    req.cookies = {};
    await handler.refresh(req, res);
    expect(res.cookie).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(400);
  });

  it('should handle a failed refresh token exchange', async () => {
    req.cookies['refresh_token'] = 'rt';
    acquireTokenByRefreshToken.mockRejectedValue(new Error('Your token is garbage'));
    await handler.refresh(req, res);
    expect(res.cookie).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Token refresh failed: Your token is garbage' });
  });

  it('should clear cookies and redirect on logout', () => {
    req.query.return_url = '/bye';
    handler.logout(req, res);
    expect(res.clearCookie).toHaveBeenCalledWith('access_token', expect.any(Object));
    expect(res.clearCookie).toHaveBeenCalledWith('id_token', expect.any(Object));
    expect(res.clearCookie).toHaveBeenCalledWith('refresh_token', expect.any(Object));
    expect(res.redirect).toHaveBeenCalledWith('/bye');
  });

  it('should clear cookies and return', () => {
    handler.logout(req, res);
    expect(res.clearCookie).toHaveBeenCalledWith('access_token', expect.any(Object));
    expect(res.clearCookie).toHaveBeenCalledWith('id_token', expect.any(Object));
    expect(res.clearCookie).toHaveBeenCalledWith('refresh_token', expect.any(Object));
    expect(res.redirect).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(204);
    expect(res.send).toHaveBeenCalled();
  });

  it('should validate the cookies', async () => {
    const publicKey = 'test-secret';
    const jwtOpts = { expiresIn: 3600, header: { kid: 'testkid', alg: 'HS256' } };
    const testAccessToken = jwt.sign({ sub: '12345' }, publicKey, jwtOpts);
    const testIdToken = jwt.sign({ sub: '12345', name: 'Test User' }, publicKey, jwtOpts);
    req.cookies['access_token'] = testAccessToken;
    req.cookies['id_token'] = testIdToken;
    getSigningKey.mockReturnValue({ getPublicKey: () => publicKey });
    await handler.validate(req, res);
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalled();
    const json = (res.json as jest.Mock).mock.calls[0][0];
    expect(json.isValidAccessToken).toBe(true);
    expect(json.isValidIdToken).toBe(true);
    expect(json.decodedAccessToken.payload.sub).toBe('12345');
    expect(json.decodedIdToken.payload.name).toBe('Test User');
  });

  it('should validate the cookies and place on the request when acting as middleware', async () => {
    const publicKey = 'test-secret';
    const jwtOpts = { expiresIn: 3600, header: { kid: 'testkid', alg: 'HS256' } };
    const testAccessToken = jwt.sign({ sub: '12345' }, publicKey, jwtOpts);
    const testIdToken = jwt.sign({ sub: '12345', name: 'Test User' }, publicKey, jwtOpts);
    req.cookies['access_token'] = testAccessToken;
    req.cookies['id_token'] = testIdToken;
    getSigningKey.mockReturnValue({ getPublicKey: () => publicKey });
    const next = jest.fn();
    await handler.validate(req, res, next);
    expect(res.status).not.toHaveBeenCalled();
    expect(res.json).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalled();
    expect((req as any).access_token?.payload.sub).toBe('12345');
    expect((req as any).id_token?.payload.name).toBe('Test User');
  });

  it('should return 401 if the both cookies cannot be validated', async () => {
    const publicKey = 'test-secret';
    const jwtOpts = { expiresIn: 3600, header: { kid: 'testkid', alg: 'HS256' } };
    const testAccessToken = jwt.sign({ sub: '12345' }, publicKey, jwtOpts);
    const testIdToken = jwt.sign({ sub: '12345', name: 'Test User' }, publicKey, jwtOpts);
    req.cookies['access_token'] = testAccessToken;
    req.cookies['id_token'] = testIdToken;
    getSigningKey.mockReturnValue({ getPublicKey: () => 'other-secret' });
    await handler.validate(req, res);
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalled();
    const json = (res.json as jest.Mock).mock.calls[0][0];
    expect(json.isValidAccessToken).toBe(false);
    expect(json.isValidIdToken).toBe(false);
    expect(json.decodedAccessToken.payload.sub).toBe('12345');
    expect(json.decodedIdToken.payload.name).toBe('Test User');
  });

  it('should return invalid for empty tokens in validateToken', async () => {
    const result: TokenValidationResult = await handler.validateTokens('', '');
    expect(result.isValidAccessToken).toBe(false);
    expect(result.isValidIdToken).toBe(false);
  });

  it('should return decoded tokens for valid tokens in validateToken', async () => {
    const publicKey = 'test-secret';
    const jwtOpts = { expiresIn: 3600, header: { kid: 'testkid', alg: 'HS256' } };
    const testAccessToken = jwt.sign({ sub: '12345' }, publicKey, jwtOpts);
    const testIdToken = jwt.sign({ sub: '12345', name: 'Test User' }, publicKey, jwtOpts);
    getSigningKey.mockReturnValue({ getPublicKey: () => publicKey });
    const result: TokenValidationResult = await handler.validateTokens(testAccessToken, testIdToken);
    expect(result.isValidAccessToken).toBe(true);
    expect(result.decodedAccessToken.header.kid).toEqual('testkid');
    expect(result.decodedAccessToken.payload.sub).toEqual('12345');
    expect(result.isValidIdToken).toBe(true);
    expect(result.decodedIdToken.payload.name).toEqual('Test User');
  });
});
