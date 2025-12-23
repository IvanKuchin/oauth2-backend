# OAuth 2.0 Backend Demo

A simple OAuth 2.0 backend implementation in Go using only the standard library, with Auth0 as the identity provider.

## Features

- OAuth 2.0 Authorization Code Flow with PKCE
- Auth0 integration for identity management
- JWT token validation
- Public, protected, and admin API endpoints
- CORS support for frontend integration
- Structured logging with slog

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

2. **Configure Auth0**
   - Create an Auth0 account at https://auth0.com
   - Create a new Application (Regular Web Application)
   - Create an API in Auth0 for your backend
   - Note down: Domain, Client ID, Client Secret, and API Identifier

3. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your Auth0 credentials
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
2. Backend redirects to Auth0 login page
3. User authenticates with Auth0
4. Auth0 redirects back to frontend callback URL with authorization code
5. Frontend sends code to `/api/v1/oauth2/token`
6. Backend exchanges code with Auth0 and returns access token
7. Frontend uses access token for API requests

## Security Features

- PKCE (Proof Key for Code Exchange) support
- State parameter validation
- JWT signature verification
- Token expiration checking
- Role-based access control
- CORS configuration

## License

MIT License
