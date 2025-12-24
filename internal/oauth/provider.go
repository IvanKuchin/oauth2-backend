package oauth

import (
	"fmt"
	"net/url"

	"github.com/ikuchin/oauth2-backend/internal/config"
)

// Provider defines the interface for OAuth providers
type Provider interface {
	GetAuthorizationURL(state, codeChallenge, redirectURI string) string
	GetTokenURL() string
	GetUserInfoURL() string
	GetIssuer() string
	GetAudience() string
	GetClientID() string
	GetClientSecret() string
	GetScopes() string
	GetJWKSEndpoint() string
	SupportsPKCE() bool
	SupportsJWT() bool
}

// BaseProvider implements common OAuth provider functionality
type BaseProvider struct {
	config *config.OAuthConfig
}

// newProvider creates a provider based on the configuration
func newProvider(cfg *config.OAuthConfig) Provider {
	switch cfg.Provider {
	case "auth0":
		return NewAuth0Provider(cfg)
	case "google":
		return NewGoogleProvider(cfg)
	case "github":
		return NewGitHubProvider(cfg)
	case "generic":
		return NewGenericProvider(cfg)
	default:
		// Default to generic provider
		return NewGenericProvider(cfg)
	}
}

// Auth0Provider implements OAuth for Auth0
type Auth0Provider struct {
	BaseProvider
}

// NewAuth0Provider creates a new Auth0 provider
func NewAuth0Provider(cfg *config.OAuthConfig) *Auth0Provider {
	return &Auth0Provider{
		BaseProvider: BaseProvider{config: cfg},
	}
}

func (p *Auth0Provider) GetAuthorizationURL(state, codeChallenge, redirectURI string) string {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", p.config.ClientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("scope", p.config.Scopes)
	params.Set("state", state)
	params.Set("audience", p.config.Audience)

	if codeChallenge != "" {
		params.Set("code_challenge", codeChallenge)
		params.Set("code_challenge_method", "S256")
	}

	return fmt.Sprintf("%s?%s", p.config.AuthorizeURL, params.Encode())
}

func (p *Auth0Provider) GetTokenURL() string     { return p.config.TokenURL }
func (p *Auth0Provider) GetUserInfoURL() string  { return p.config.UserInfoURL }
func (p *Auth0Provider) GetIssuer() string       { return p.config.Issuer }
func (p *Auth0Provider) GetAudience() string     { return p.config.Audience }
func (p *Auth0Provider) GetClientID() string     { return p.config.ClientID }
func (p *Auth0Provider) GetClientSecret() string { return p.config.ClientSecret }
func (p *Auth0Provider) GetScopes() string       { return p.config.Scopes }
func (p *Auth0Provider) GetJWKSEndpoint() string { return p.config.JWKSEndpoint }
func (p *Auth0Provider) SupportsPKCE() bool      { return true }
func (p *Auth0Provider) SupportsJWT() bool       { return true }

// GoogleProvider implements OAuth for Google
type GoogleProvider struct {
	BaseProvider
}

// NewGoogleProvider creates a new Google provider
func NewGoogleProvider(cfg *config.OAuthConfig) *GoogleProvider {
	return &GoogleProvider{
		BaseProvider: BaseProvider{config: cfg},
	}
}

func (p *GoogleProvider) GetAuthorizationURL(state, codeChallenge, redirectURI string) string {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", p.config.ClientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("scope", p.config.Scopes)
	params.Set("state", state)
	params.Set("access_type", "offline") // Get refresh token
	params.Set("prompt", "consent")      // Force consent screen to get refresh token

	if codeChallenge != "" {
		params.Set("code_challenge", codeChallenge)
		params.Set("code_challenge_method", "S256")
	}

	return fmt.Sprintf("%s?%s", p.config.AuthorizeURL, params.Encode())
}

func (p *GoogleProvider) GetTokenURL() string     { return p.config.TokenURL }
func (p *GoogleProvider) GetUserInfoURL() string  { return p.config.UserInfoURL }
func (p *GoogleProvider) GetIssuer() string       { return p.config.Issuer }
func (p *GoogleProvider) GetAudience() string     { return p.config.Audience }
func (p *GoogleProvider) GetClientID() string     { return p.config.ClientID }
func (p *GoogleProvider) GetClientSecret() string { return p.config.ClientSecret }
func (p *GoogleProvider) GetScopes() string       { return p.config.Scopes }
func (p *GoogleProvider) GetJWKSEndpoint() string { return p.config.JWKSEndpoint }
func (p *GoogleProvider) SupportsPKCE() bool      { return true }
func (p *GoogleProvider) SupportsJWT() bool       { return true }

// GitHubProvider implements OAuth for GitHub
type GitHubProvider struct {
	BaseProvider
}

// NewGitHubProvider creates a new GitHub provider
func NewGitHubProvider(cfg *config.OAuthConfig) *GitHubProvider {
	return &GitHubProvider{
		BaseProvider: BaseProvider{config: cfg},
	}
}

func (p *GitHubProvider) GetAuthorizationURL(state, codeChallenge, redirectURI string) string {
	params := url.Values{}
	params.Set("client_id", p.config.ClientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("scope", p.config.Scopes)
	params.Set("state", state)

	// GitHub doesn't support PKCE in the standard way
	// It uses a different flow

	return fmt.Sprintf("%s?%s", p.config.AuthorizeURL, params.Encode())
}

func (p *GitHubProvider) GetTokenURL() string     { return p.config.TokenURL }
func (p *GitHubProvider) GetUserInfoURL() string  { return p.config.UserInfoURL }
func (p *GitHubProvider) GetIssuer() string       { return p.config.Issuer }
func (p *GitHubProvider) GetAudience() string     { return p.config.Audience }
func (p *GitHubProvider) GetClientID() string     { return p.config.ClientID }
func (p *GitHubProvider) GetClientSecret() string { return p.config.ClientSecret }
func (p *GitHubProvider) GetScopes() string       { return p.config.Scopes }
func (p *GitHubProvider) GetJWKSEndpoint() string { return p.config.JWKSEndpoint }
func (p *GitHubProvider) SupportsPKCE() bool      { return false } // GitHub doesn't support PKCE
func (p *GitHubProvider) SupportsJWT() bool       { return false } // GitHub uses opaque tokens

// GenericProvider implements OAuth for generic providers
type GenericProvider struct {
	BaseProvider
}

// NewGenericProvider creates a new generic provider
func NewGenericProvider(cfg *config.OAuthConfig) *GenericProvider {
	return &GenericProvider{
		BaseProvider: BaseProvider{config: cfg},
	}
}

func (p *GenericProvider) GetAuthorizationURL(state, codeChallenge, redirectURI string) string {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", p.config.ClientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("scope", p.config.Scopes)
	params.Set("state", state)

	if p.config.Audience != "" {
		params.Set("audience", p.config.Audience)
	}

	if codeChallenge != "" {
		params.Set("code_challenge", codeChallenge)
		params.Set("code_challenge_method", "S256")
	}

	return fmt.Sprintf("%s?%s", p.config.AuthorizeURL, params.Encode())
}

func (p *GenericProvider) GetTokenURL() string     { return p.config.TokenURL }
func (p *GenericProvider) GetUserInfoURL() string  { return p.config.UserInfoURL }
func (p *GenericProvider) GetIssuer() string       { return p.config.Issuer }
func (p *GenericProvider) GetAudience() string     { return p.config.Audience }
func (p *GenericProvider) GetClientID() string     { return p.config.ClientID }
func (p *GenericProvider) GetClientSecret() string { return p.config.ClientSecret }
func (p *GenericProvider) GetScopes() string       { return p.config.Scopes }
func (p *GenericProvider) GetJWKSEndpoint() string { return p.config.JWKSEndpoint }
func (p *GenericProvider) SupportsPKCE() bool      { return true } // Assume support
func (p *GenericProvider) SupportsJWT() bool       { return p.config.JWKSEndpoint != "" }
