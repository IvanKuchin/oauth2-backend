# OAuth 2.0 Backend Demo

A flexible OAuth 2.0 backend implementation in Go using only the standard library, supporting multiple identity providers including Auth0, Google, GitHub, and any generic OAuth 2.0 provider.

## Features

- OAuth 2.0 Authorization Code Flow with PKCE
- Multi-provider support (Auth0, Google, GitHub, custom providers)
- JWT token validation
- Public, protected, and admin API endpoints
- CORS support for frontend integration
- Structured logging with slog

## Supported Identity Providers

- **Auth0** - Full OAuth 2.0 + OIDC support with JWT validation
- **Google** - OAuth 2.0 with JWT validation
- **GitHub** - OAuth 2.0 (opaque tokens, no JWT)
- **Generic** - Any OAuth 2.0 compatible provider

## Project Structure

```
.
├── cmd/
│   └── server/
│       └── main.go           # Application entry point
├── internal/
│   ├── config/
│   │   └── config.go         # Configuration management
│   ├── handlers/
│   │   ├── oauth.go          # OAuth endpoints
│   │   └── api.go            # API endpoints
│   ├── middleware/
│   │   ├── cors.go           # CORS middleware
│   │   ├── logging.go        # Logging middleware
│   │   └── auth.go           # Authentication middleware
│   └── oauth/
│       ├── client.go         # OAuth client
│       └── jwt.go            # JWT validation
├── .env.example              # Environment variables template
├── Dockerfile                # Production Docker image
├── docker-compose.yml        # Docker Compose configuration
├── go.mod                    # Go module file
└── README.md                 # This file
```

## Setup

1. **Clone the repository**

2. **Configure Identity Provider**
   
   Choose your OAuth provider and configure accordingly:

   ### Auth0
   - Create an Auth0 account at https://auth0.com
   - Create a new Application (Regular Web Application)
   - Create an API in Auth0 for your backend
   - Note down: Domain, Client ID, Client Secret, and API Identifier

   ### Google
   - Go to Google Cloud Console (https://console.cloud.google.com)
   - Create a new project or select existing one
   - Enable Google+ API
   - Create OAuth 2.0 credentials (Web application)
   - Note down: Client ID and Client Secret
   - Add authorized redirect URI: `http://localhost:3000/callback`

   ### GitHub
   - Go to GitHub Settings → Developer settings → OAuth Apps
   - Create a new OAuth App
   - Note down: Client ID and Client Secret
   - Set Authorization callback URL: `http://localhost:3000/callback`

   ### Generic OAuth Provider
   - Obtain OAuth credentials from your provider
   - Get the authorization, token, and JWKS endpoints

3. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your provider credentials
   ```

   Example for Auth0:
   ```bash
   OAUTH_PROVIDER=auth0
   OAUTH_DOMAIN=your-tenant.auth0.com
   OAUTH_CLIENT_ID=your-client-id
   OAUTH_CLIENT_SECRET=your-client-secret
   OAUTH_AUDIENCE=https://your-api-identifier
   OAUTH_CALLBACK_URL=http://localhost:3000/callback
   ```

   Example for Google:
   ```bash
   OAUTH_PROVIDER=google
   OAUTH_DOMAIN=accounts.google.com
   OAUTH_CLIENT_ID=your-client-id.apps.googleusercontent.com
   OAUTH_CLIENT_SECRET=your-client-secret
   OAUTH_CALLBACK_URL=http://localhost:3000/callback
   ```

   Example for GitHub:
   ```bash
   OAUTH_PROVIDER=github
   OAUTH_DOMAIN=github.com
   OAUTH_CLIENT_ID=your-client-id
   OAUTH_CLIENT_SECRET=your-client-secret
   OAUTH_CALLBACK_URL=http://localhost:3000/callback
   ```

4. **Install Go** (version 1.21 or higher)

## Running the Application

### Development Mode

```bash
go run cmd/server/main.go
```

The server will start on `http://localhost:8080`

### Production Mode with Docker

```bash
docker-compose up --build
```

## API Endpoints

### OAuth Endpoints

- `GET /api/v1/oauth2/authorize` - Initiates OAuth flow, redirects to Auth0
- `POST /api/v1/oauth2/token` - Exchanges authorization code for access token

### API Endpoints

- `GET /api/v1/public` - Public endpoint (no authentication required)
- `GET /api/v1/protected` - Protected endpoint (requires valid JWT)
- `GET /api/v1/admin` - Admin endpoint (requires JWT with admin role)

## Testing with curl

### Public Endpoint
```bash
curl http://localhost:8080/api/v1/public
```

### Protected Endpoint
```bash
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     http://localhost:8080/api/v1/protected
```

### Admin Endpoint
```bash
curl -H "Authorization: Bearer YOUR_ADMIN_ACCESS_TOKEN" \
     http://localhost:8080/api/v1/admin
```

## OAuth Flow

1. Frontend redirects user to `/api/v1/oauth2/authorize` with PKCE parameters
2. Backend redirects to the configured identity provider's login page
3. User authenticates with the identity provider
4. Provider redirects back to frontend callback URL with authorization code
5. Frontend sends code to `/api/v1/oauth2/token`
6. Backend exchanges code with provider and returns access token
7. Frontend uses access token for API requests

## Provider-Specific Notes

### Auth0
- Supports PKCE
- Returns JWT tokens
- Full JWT validation with JWKS
- Supports custom scopes and permissions

### Google
- Supports PKCE
- Returns JWT tokens (ID tokens)
- JWT validation with Google's JWKS
- Standard scopes: `openid profile email`

### GitHub
- Does not support PKCE
- Returns opaque access tokens (not JWT)
- No JWT validation (tokens verified via GitHub API)
- Standard scopes: `read:user user:email`

### Generic Provider
- Configurable endpoints
- Optional PKCE support
- Optional JWT validation (if JWKS endpoint provided)
- Customizable scopes

## Security Features

- PKCE (Proof Key for Code Exchange) support
- State parameter validation
- JWT signature verification
- Token expiration checking
- Role-based access control
- CORS configuration

## License

MIT License
