# Copilot Instructions for the Azure SSO Handler

This repository contains a handler for Azure Single Sign-On (SSO) integration. The handler is designed to facilitate authentication and authorization processes using Azure's SSO capabilities.

The code in this repository is written in Typescript and leverages the Azure SDK for seamless integration with Azure services.

The process flow is as follows:

1. The handler receives an authentication request to the /login endpoint
2. If this is the first request, the handler redirects the user to the Azure SSO login page
3. After successful authentication, Azure redirects the user back to the /login endpoint with an authorization code
4. The handler calls an Azure token api to exchanges the authorization code for an access_token, id_token, and refresh_token
5. The handler responds to the client with http-only cookies containing the tokens
6. The client uses these tokens for subsequent authenticated requests
7. The handler provides a /refresh endpoint to refresh tokens using the refresh_token when they expire
8. The handler provides a /logout endpoint to clear the authentication cookies and log the user out
9. The handler includes error handling to manage failed authentication attempts and token refresh failures
10. The handler is designed to be secure, using http-only cookies to store tokens and ensuring that sensitive information is not exposed to the client-side
11. The handler is modular and can be easily integrated into existing applications that require Azure SSO functionality
12. The handler includes configuration options to customize the Azure SSO integration. These include client ID, client secret, tenant ID, scope and redirect URI
13. The handler includes logging functionality to track authentication events and errors for monitoring and debugging purposes
14. The handler is designed to be scalable and can handle multiple concurrent authentication requests efficiently
15. The handler includes unit tests to ensure the reliability and correctness of the authentication flow and token management
16. The handler is documented with clear instructions on how to set up and configure Azure SSO integration, including prerequisites and environment variables needed for deployment
17. The handler supports multiple environments (development, staging, production) with environment-specific configurations for Azure SSO integration
18. The handler is compliant with relevant security standards and best practices for handling authentication and sensitive data
19. The handler is optimized for performance, minimizing latency in the authentication process and token exchanges
20. The handler validates the tokens received from Azure to ensure they are legitimate and have not been tampered with
