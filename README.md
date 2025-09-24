# azure-sso-handler

1. Assumes use of `express` with all of its request / response handling.
1. The Azure access token never seems to pass verification against the keystore but the id token is fine. For this reason only one valid token is required in order to be authenticated.

``` ts
const config: AzureSSOConfig = {
  clientId: 'clientId';
  clientSecret: 'clientSecret';
  tenantId: 'tenantId';
  scope: 'openid offline_access';
  redirectUri: 'https://my.redirect.url';
  cookieNames: {
    accessToken: 'access_token';
    idToken: 'id_token';
    refreshToken: 'refresh_token';
  }
};

const handler = new AzureSSOHandler(config);
```

1. `handler.login(req, res)` to redirect to Azure for authentication. Provide a `return_url` query parameter to specify where to eventually redirect back to once auth is complete. The login flow necessarily involves redirects. Your login button should set the browser location to the appropriate `/login` endpoint. Other functions can be used with javascript fetch requests
1. `handler.handleAzureCallback(req, res)` to handle the Azure callback with the code. This redirects to the `return_url` with cookies set for each of the Azure tokens.
1. `handler.refresh(req, res)` to refresh the tokens. Uses the refresh_token from the cookies.
1. `handler.logout(req, res)` to clear cookies. You can provide a `return_url` query parameter to redirect back to, or not if you want to logout using a fetch request
1. `handler.validate(req, res)` to respond with decoded tokens or 401
1. `handler.validate(req, res, next)` to using as middlware, setting req[cookieNames.accessToken] and req[cookieNames.idToken] with the decoded access and id tokens (or responding with 401)
1. `handler.validateTokens(accessToken, idToken)` to validate and decode the tokens