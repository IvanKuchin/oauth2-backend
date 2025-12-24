package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Config holds all application configuration
type Config struct {
	Server   ServerConfig
	OAuth    OAuthConfig
	Frontend FrontendConfig
}

// ServerConfig contains server settings
type ServerConfig struct {
	Host string
	Port string
}

// OAuthConfig contains OAuth provider settings
type OAuthConfig struct {
	Provider     string // "auth0", "google", "github", "generic"
	Domain       string
	ClientID     string
	ClientSecret string
	Audience     string
	CallbackURL  string
	Issuer       string
	AuthorizeURL string // For generic provider
	TokenURL     string // For generic provider
	UserInfoURL  string // For generic provider
	Scopes       string // Space-separated scopes
	JWKSEndpoint string // JWKS endpoint for JWT validation
}

// Auth0Config contains Auth0 OAuth settings (deprecated, use OAuthConfig)
type Auth0Config struct {
	Domain       string
	ClientID     string
	ClientSecret string
	Audience     string
	CallbackURL  string
	Issuer       string
}

// FrontendConfig contains frontend settings
type FrontendConfig struct {
	URL string
}

// Load reads configuration from environment variables
func Load() (*Config, error) {
	// Load .env file if it exists
	if err := loadEnvFile(".env"); err != nil {
		// .env is optional, continue without it
	}

	provider := getEnv("OAUTH_PROVIDER", "auth0")

	cfg := &Config{
		Server: ServerConfig{
			Host: getEnv("SERVER_HOST", "localhost"),
			Port: getEnv("SERVER_PORT", "8080"),
		},
		OAuth: OAuthConfig{
			Provider:     provider,
			Domain:       getEnv("OAUTH_DOMAIN", getEnv("AUTH0_DOMAIN", "")),
			ClientID:     getEnv("OAUTH_CLIENT_ID", getEnv("AUTH0_CLIENT_ID", "")),
			ClientSecret: getEnv("OAUTH_CLIENT_SECRET", getEnv("AUTH0_CLIENT_SECRET", "")),
			Audience:     getEnv("OAUTH_AUDIENCE", getEnv("AUTH0_AUDIENCE", "")),
			CallbackURL:  getEnv("OAUTH_CALLBACK_URL", getEnv("AUTH0_CALLBACK_URL", "")),
			Issuer:       getEnv("OAUTH_ISSUER", getEnv("JWT_ISSUER", "")),
			AuthorizeURL: getEnv("OAUTH_AUTHORIZE_URL", ""),
			TokenURL:     getEnv("OAUTH_TOKEN_URL", ""),
			UserInfoURL:  getEnv("OAUTH_USERINFO_URL", ""),
			Scopes:       getEnv("OAUTH_SCOPES", "openid profile email"),
			JWKSEndpoint: getEnv("OAUTH_JWKS_ENDPOINT", ""),
		},
		Frontend: FrontendConfig{
			URL: getEnv("FRONTEND_URL", "http://localhost:3000"),
		},
	}

	// Validate required fields
	if cfg.OAuth.Domain == "" {
		return nil, fmt.Errorf("OAUTH_DOMAIN is required")
	}
	if cfg.OAuth.ClientID == "" {
		return nil, fmt.Errorf("OAUTH_CLIENT_ID is required")
	}
	if cfg.OAuth.CallbackURL == "" {
		return nil, fmt.Errorf("OAUTH_CALLBACK_URL is required")
	}

	// Set provider-specific defaults
	if err := setProviderDefaults(&cfg.OAuth); err != nil {
		return nil, err
	}

	return cfg, nil
}

// setProviderDefaults sets default values based on the provider
func setProviderDefaults(cfg *OAuthConfig) error {
	switch cfg.Provider {
	case "auth0":
		if cfg.Issuer == "" {
			cfg.Issuer = fmt.Sprintf("https://%s/", cfg.Domain)
		}
		if cfg.AuthorizeURL == "" {
			cfg.AuthorizeURL = fmt.Sprintf("https://%s/authorize", cfg.Domain)
		}
		if cfg.TokenURL == "" {
			cfg.TokenURL = fmt.Sprintf("https://%s/oauth/token", cfg.Domain)
		}
		if cfg.UserInfoURL == "" {
			cfg.UserInfoURL = fmt.Sprintf("https://%s/userinfo", cfg.Domain)
		}
		if cfg.JWKSEndpoint == "" {
			cfg.JWKSEndpoint = fmt.Sprintf("https://%s/.well-known/jwks.json", cfg.Domain)
		}
		if cfg.Audience == "" {
			return fmt.Errorf("OAUTH_AUDIENCE is required for Auth0")
		}

	case "google":
		if cfg.Issuer == "" {
			cfg.Issuer = "https://accounts.google.com"
		}
		if cfg.AuthorizeURL == "" {
			cfg.AuthorizeURL = "https://accounts.google.com/o/oauth2/v2/auth"
		}
		if cfg.TokenURL == "" {
			cfg.TokenURL = "https://oauth2.googleapis.com/token"
		}
		if cfg.UserInfoURL == "" {
			cfg.UserInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"
		}
		if cfg.JWKSEndpoint == "" {
			cfg.JWKSEndpoint = "https://www.googleapis.com/oauth2/v3/certs"
		}
		// Google doesn't use audience in the same way
		if cfg.Audience == "" {
			cfg.Audience = cfg.ClientID
		}

	case "github":
		if cfg.Issuer == "" {
			cfg.Issuer = "https://github.com"
		}
		if cfg.AuthorizeURL == "" {
			cfg.AuthorizeURL = "https://github.com/login/oauth/authorize"
		}
		if cfg.TokenURL == "" {
			cfg.TokenURL = "https://github.com/login/oauth/access_token"
		}
		if cfg.UserInfoURL == "" {
			cfg.UserInfoURL = "https://api.github.com/user"
		}
		// GitHub doesn't use JWT tokens by default, so no JWKS endpoint
		cfg.JWKSEndpoint = ""
		if cfg.Scopes == "" {
			cfg.Scopes = "read:user user:email"
		}

	case "generic":
		// For generic provider, all URLs must be explicitly configured
		if cfg.AuthorizeURL == "" {
			return fmt.Errorf("OAUTH_AUTHORIZE_URL is required for generic provider")
		}
		if cfg.TokenURL == "" {
			return fmt.Errorf("OAUTH_TOKEN_URL is required for generic provider")
		}
		if cfg.Issuer == "" {
			cfg.Issuer = fmt.Sprintf("https://%s/", cfg.Domain)
		}

	default:
		return fmt.Errorf("unsupported OAuth provider: %s (supported: auth0, google, github, generic)", cfg.Provider)
	}

	return nil
}

// getEnv retrieves an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// loadEnvFile loads environment variables from a file
func loadEnvFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse KEY=VALUE
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Only set if not already set in environment
		if os.Getenv(key) == "" {
			os.Setenv(key, value)
		}
	}

	return scanner.Err()
}
