import { AzureSSOHandler, AzureSSOConfig, TokenValidationResult, defaultCookieNames } from './ssoHandler';
import jwt from 'jsonwebtoken';

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
  beforeEach(() => {
    handler = new AzureSSOHandler(config);
  });

  it('should build the correct authorize URL', () => {
    const req = { query: { return_url: '/dashboard' } };
    const url = handler['_buildAuthorizeUrl'](req);
    expect(url).toContain(config.tenantId);
    expect(url).toContain(config.clientId);
    expect(url).toContain(encodeURIComponent('/dashboard'));
  });

  it('should redirect using _redirect (express)', () => {
    const res = { redirect: jest.fn() };
    handler['_redirect'](res, 'http://test-url');
    expect(res.redirect).toHaveBeenCalledWith('http://test-url');
  });

  it('should redirect using _redirect (node)', () => {
    const res = {
      writeHead: jest.fn(),
      end: jest.fn(),
    };
    handler['_redirect'](res, 'http://test-url');
    expect(res.writeHead).toHaveBeenCalledWith(302, { Location: 'http://test-url' });
    expect(res.end).toHaveBeenCalled();
  });

  it('should set cookies with _setCookies', () => {
    const response = {
      accessToken: 'at',
      idToken: 'it',
      refreshToken: 'rt',
      expires_in: 3600,
    };
    const res = { cookie: jest.fn() };
    handler['_setCookies'](response, res);
    expect(res.cookie).toHaveBeenCalledWith('access_token', 'at', expect.any(Object));
    expect(res.cookie).toHaveBeenCalledWith('id_token', 'it', expect.any(Object));
    expect(res.cookie).toHaveBeenCalledWith('refresh_token', 'rt', expect.any(Object));
  });

  it('should clear cookies on logout', () => {
    const res = { clearCookie: jest.fn(), redirect: jest.fn() };
    const req = { query: { return_url: '/bye' } };
    handler.logout(req, res);
    expect(res.clearCookie).toHaveBeenCalledWith('access_token', expect.any(Object));
    expect(res.clearCookie).toHaveBeenCalledWith('id_token', expect.any(Object));
    expect(res.clearCookie).toHaveBeenCalledWith('refresh_token', expect.any(Object));
    expect(res.redirect).toHaveBeenCalled();
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
    handler['jwksClient'].getSigningKey = jest.fn().mockReturnValue({ getPublicKey: () => publicKey });
    const result: TokenValidationResult = await handler.validateTokens(testAccessToken, testIdToken);
    expect(result.isValidAccessToken).toBe(true);
    expect(result.decodedAccessToken.header.kid).toEqual('testkid');
    expect(result.decodedAccessToken.payload.sub).toEqual('12345');
    expect(result.isValidIdToken).toBe(true);
    expect(result.decodedIdToken.payload.name).toEqual('Test User');
  });
});
