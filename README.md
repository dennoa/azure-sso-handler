# azure-sso-handler

``` ts
const config: AzureSSOConfig = {
  clientId: 'clientId';
  clientSecret: 'clientSecret';
  tenantId: 'tenantId';
  scope: 'scope1,scope2';
  redirectUri: 'https://my.redirect.url';
  shouldLogoutFromAzure?: false;
  cookieNames: {
    accessToken: 'access_token';
    idToken: 'id_token';
    refreshToken: 'refresh_token';
  }
};

const handler = new AzureSSOHandler(config);
```

1. `handler.login(req, res)` to redirect to Azure for authentication. Provide a `return_url` query parameter to specify where to eventually redirect back to once auth is complete.
1. `handler.handleAzureCallback(req, res)` to handle the Azure callback with the code. This redirects to the `return_url` with cookies set for each of the Azure tokens.
1. `handler.refresh(req, res)` to refresh the tokens. Uses the refresh_token from the cookies.
1. `handler.logout(req, res)` to clear cookies. Provide a `return_url` query parameter to redirect back to. If configured with `shouldLogoutFromAzure: true` then the logout will also logout of Azure (normally don't want to do this).
1. `handler.validate(req, res)` to respond with decoded tokens or 401
1. `handler.validate(req, res, next)` to set req[cookieNames.accessToken] and req[cookieNames.idToken] with the decoded access and id tokens, or respond with 401
1. `handler.validateTokens(accessToken, idToken)` to validate and decode the tokens