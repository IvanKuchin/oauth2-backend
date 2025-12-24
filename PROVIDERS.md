# OAuth Provider Configuration Guide

This document provides detailed configuration instructions for each supported OAuth provider.

## Table of Contents
- [Auth0](#auth0)
- [Google](#google)
- [GitHub](#github)
- [Generic OAuth Provider](#generic-oauth-provider)

---

## Auth0

Auth0 is a comprehensive identity platform that fully supports OAuth 2.0 and OpenID Connect.

### Setup Steps

1. **Create Auth0 Account**
   - Go to https://auth0.com and sign up
   - Create a new tenant

2. **Create Application**
   - Navigate to Applications → Applications
   - Click "Create Application"
   - Choose "Regular Web Application"
   - Note the Domain, Client ID, and Client Secret

3. **Create API**
   - Navigate to Applications → APIs
   - Click "Create API"
   - Set a name and identifier (e.g., `https://api.example.com`)
   - Note the API Identifier (this is your Audience)

4. **Configure Application**
   - In your application settings, add callback URLs
   - Allowed Callback URLs: `http://localhost:3000/callback`
   - Allowed Web Origins: `http://localhost:3000`

### Environment Configuration

```bash
OAUTH_PROVIDER=auth0
OAUTH_DOMAIN=your-tenant.auth0.com
OAUTH_CLIENT_ID=your_auth0_client_id
OAUTH_CLIENT_SECRET=your_auth0_client_secret
OAUTH_AUDIENCE=https://your-api-identifier
OAUTH_CALLBACK_URL=http://localhost:3000/callback
```

### Features
- ✅ PKCE Support
- ✅ JWT Tokens
- ✅ JWT Validation
- ✅ Custom Scopes
- ✅ Permissions/Roles

### Default Scopes
`openid profile email`

---

## Google

Google OAuth 2.0 provides authentication through Google accounts.

### Setup Steps

1. **Create Google Cloud Project**
   - Go to https://console.cloud.google.com
   - Create a new project or select existing one

2. **Enable APIs**
   - Navigate to APIs & Services → Library
   - Search for and enable "Google+ API"

3. **Create OAuth Credentials**
   - Navigate to APIs & Services → Credentials
   - Click "Create Credentials" → "OAuth client ID"
   - Choose "Web application"
   - Add authorized redirect URI: `http://localhost:3000/callback`
   - Note the Client ID and Client Secret

4. **Configure OAuth Consent Screen**
   - Configure the OAuth consent screen with your application details
   - Add scopes: email, profile, openid

### Environment Configuration

```bash
OAUTH_PROVIDER=google
OAUTH_DOMAIN=accounts.google.com
OAUTH_CLIENT_ID=your_google_client_id.apps.googleusercontent.com
OAUTH_CLIENT_SECRET=your_google_client_secret
OAUTH_CALLBACK_URL=http://localhost:3000/callback
```

### Features
- ✅ PKCE Support
- ✅ JWT Tokens (ID Token)
- ✅ JWT Validation
- ✅ Standard OIDC Scopes

### Default Scopes
`openid profile email`

### Notes
- Google returns both an access token and an ID token
- The ID token is a JWT that contains user information
- Access tokens are used for Google API calls

---

## GitHub

GitHub OAuth provides authentication through GitHub accounts.

### Setup Steps

1. **Register OAuth App**
   - Go to GitHub Settings → Developer settings → OAuth Apps
   - Click "New OAuth App"

2. **Configure Application**
   - Application name: Your app name
   - Homepage URL: `http://localhost:3000`
   - Authorization callback URL: `http://localhost:3000/callback`
   - Note the Client ID and Client Secret

### Environment Configuration

```bash
OAUTH_PROVIDER=github
OAUTH_DOMAIN=github.com
OAUTH_CLIENT_ID=your_github_client_id
OAUTH_CLIENT_SECRET=your_github_client_secret
OAUTH_CALLBACK_URL=http://localhost:3000/callback
```

### Features
- ❌ No PKCE Support
- ❌ No JWT Tokens (opaque tokens)
- ❌ No JWT Validation
- ✅ User API for token verification

### Default Scopes
`read:user user:email`

### Notes
- GitHub returns opaque access tokens, not JWTs
- JWT validation is automatically disabled for GitHub
- Tokens must be verified using GitHub's API endpoints
- Limited to GitHub-specific scopes

---

## Generic OAuth Provider

Use this configuration for any OAuth 2.0 compatible provider not listed above (e.g., Okta, Keycloak, custom OAuth servers).

### Setup Steps

1. **Obtain Provider Information**
   - Get OAuth credentials from your provider
   - Locate the authorization endpoint
   - Locate the token endpoint
   - Locate the JWKS endpoint (if JWT validation is needed)
   - Locate the userinfo endpoint (optional)

2. **Check Provider Capabilities**
   - Verify if PKCE is supported
   - Check if JWT tokens are issued
   - Confirm available scopes

### Environment Configuration

```bash
OAUTH_PROVIDER=generic
OAUTH_DOMAIN=your-oauth-provider.com
OAUTH_CLIENT_ID=your_client_id
OAUTH_CLIENT_SECRET=your_client_secret
OAUTH_AUDIENCE=your_api_identifier
OAUTH_CALLBACK_URL=http://localhost:3000/callback
OAUTH_ISSUER=https://your-oauth-provider.com/
OAUTH_AUTHORIZE_URL=https://your-oauth-provider.com/oauth/authorize
OAUTH_TOKEN_URL=https://your-oauth-provider.com/oauth/token
OAUTH_USERINFO_URL=https://your-oauth-provider.com/oauth/userinfo
OAUTH_JWKS_ENDPOINT=https://your-oauth-provider.com/.well-known/jwks.json
OAUTH_SCOPES=openid profile email
```

### Required Variables
- `OAUTH_AUTHORIZE_URL` - Authorization endpoint
- `OAUTH_TOKEN_URL` - Token exchange endpoint

### Optional Variables
- `OAUTH_USERINFO_URL` - User information endpoint
- `OAUTH_JWKS_ENDPOINT` - JWKS endpoint for JWT validation
- `OAUTH_ISSUER` - JWT issuer claim
- `OAUTH_AUDIENCE` - JWT audience claim
- `OAUTH_SCOPES` - Space-separated list of scopes

### Features
- ✅ Configurable PKCE Support
- ✅ Optional JWT Tokens
- ✅ Optional JWT Validation
- ✅ Custom Scopes

### Example: Okta

```bash
OAUTH_PROVIDER=generic
OAUTH_DOMAIN=your-domain.okta.com
OAUTH_CLIENT_ID=your_okta_client_id
OAUTH_CLIENT_SECRET=your_okta_client_secret
OAUTH_CALLBACK_URL=http://localhost:3000/callback
OAUTH_ISSUER=https://your-domain.okta.com/oauth2/default
OAUTH_AUTHORIZE_URL=https://your-domain.okta.com/oauth2/default/v1/authorize
OAUTH_TOKEN_URL=https://your-domain.okta.com/oauth2/default/v1/token
OAUTH_JWKS_ENDPOINT=https://your-domain.okta.com/oauth2/default/v1/keys
OAUTH_SCOPES=openid profile email
```

### Example: Keycloak

```bash
OAUTH_PROVIDER=generic
OAUTH_DOMAIN=your-keycloak-server.com
OAUTH_CLIENT_ID=your_client_id
OAUTH_CLIENT_SECRET=your_client_secret
OAUTH_CALLBACK_URL=http://localhost:3000/callback
OAUTH_ISSUER=https://your-keycloak-server.com/realms/your-realm
OAUTH_AUTHORIZE_URL=https://your-keycloak-server.com/realms/your-realm/protocol/openid-connect/auth
OAUTH_TOKEN_URL=https://your-keycloak-server.com/realms/your-realm/protocol/openid-connect/token
OAUTH_JWKS_ENDPOINT=https://your-keycloak-server.com/realms/your-realm/protocol/openid-connect/certs
OAUTH_SCOPES=openid profile email
```

---

## Switching Providers

To switch between providers, simply change the `OAUTH_PROVIDER` variable and update the corresponding configuration variables. The backend will automatically use the correct endpoints and behavior for the selected provider.

```bash
# Switch from Auth0 to Google
OAUTH_PROVIDER=google  # Change this
OAUTH_DOMAIN=accounts.google.com
OAUTH_CLIENT_ID=your_google_client_id.apps.googleusercontent.com
OAUTH_CLIENT_SECRET=your_google_client_secret
OAUTH_CALLBACK_URL=http://localhost:3000/callback
```

## Backward Compatibility

The legacy `AUTH0_*` environment variables are still supported for backward compatibility but are deprecated. They will be automatically mapped to the new `OAUTH_*` variables if `OAUTH_PROVIDER` is not set or is set to `auth0`.

```bash
# Old (deprecated but still works)
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_CLIENT_ID=your_client_id
AUTH0_CLIENT_SECRET=your_client_secret
AUTH0_AUDIENCE=https://your-api-identifier
AUTH0_CALLBACK_URL=http://localhost:3000/callback

# New (recommended)
OAUTH_PROVIDER=auth0
OAUTH_DOMAIN=your-tenant.auth0.com
OAUTH_CLIENT_ID=your_client_id
OAUTH_CLIENT_SECRET=your_client_secret
OAUTH_AUDIENCE=https://your-api-identifier
OAUTH_CALLBACK_URL=http://localhost:3000/callback
```
