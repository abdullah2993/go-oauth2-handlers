// Package oauth provides HTTP handlers for OAuth2 authentication with popular
// providers like Google and Facebook.
//
// The package offers a simple, handler-based API that integrates seamlessly with
// net/http. It handles the OAuth2 flow including state management, token exchange,
// and user information retrieval.
//
// Basic usage:
//
//	loginHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//	    user, _ := oauth.FromUserContext(r.Context())
//	    fmt.Fprintf(w, "Welcome, %s!", user.Name)
//	})
//
//	errorHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//	    err, _ := oauth.FromErrorContext(r.Context())
//	    http.Error(w, err.Error(), http.StatusUnauthorized)
//	})
//
//	handler := oauth.New(loginHandler, errorHandler,
//	    oauth.WithGoogle("client-id", "client-secret", "http://localhost/callback"),
//	)
//
//	http.Handle("/auth/", http.StripPrefix("/auth", handler))
package oauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// Default configuration values. These can be overridden using Option functions.
const (
	// DefaultMaxUserInfoResponseSize is the default maximum size of the user info
	// response body (1MB). This prevents memory exhaustion from malicious or
	// malformed responses.
	DefaultMaxUserInfoResponseSize int64 = 1 << 20

	// DefaultStateExpiration is the default duration for how long OAuth states
	// remain valid before expiring. States not used within this duration will
	// be considered invalid.
	DefaultStateExpiration = 10 * time.Minute

	// DefaultStateCleanupInterval is the default interval at which the background
	// goroutine runs to clean up expired OAuth states from memory.
	DefaultStateCleanupInterval = 10 * time.Minute
)

// User represents the authenticated user information retrieved from an OAuth provider.
// The fields are normalized across different providers to provide a consistent interface.
type User struct {
	// ID is the unique identifier for the user from the OAuth provider.
	ID string

	// Name is the user's full display name.
	Name string

	// FirstName is the user's first or given name.
	FirstName string

	// LastName is the user's last or family name.
	LastName string

	// Email is the user's email address.
	Email string

	// Avatar is the URL to the user's profile picture.
	Avatar string

	// Provider identifies which OAuth provider authenticated this user.
	Provider ProviderType
}

// ProviderType identifies an OAuth provider.
// Use the predefined constants (ProviderGoogle, ProviderFacebook) or create
// custom provider types for other OAuth providers.
type ProviderType string

// oauthState stores the state information for an in-progress OAuth flow.
type oauthState struct {
	redirectLink string
	provider     string
	createdAt    time.Time
}

// ProviderConfig contains the configuration for an OAuth provider.
// Use the helper functions like GoogleProviderConfig and FacebookProviderConfig
// to create configurations for supported providers, or create custom configurations
// for other OAuth providers.
//
// Pass to New() using WithProvider:
//
//	oauth.New(loginHandler, errorHandler,
//	    oauth.WithProvider(oauth.GoogleProviderConfig(...)),
//	)
type ProviderConfig struct {
	// Provider is the identifier for this OAuth provider.
	Provider ProviderType

	// Config is the underlying oauth2.Config for this provider.
	*oauth2.Config

	// InfoEndpoint is the URL template for fetching user information.
	// It should contain a %s placeholder for the access token.
	InfoEndpoint string

	// Unmarshal parses the user info response from the provider into a User struct.
	Unmarshal func(r io.Reader) (*User, error)
}

// config holds the internal configuration for the OAuth handler.
type config struct {
	providers               []*ProviderConfig
	maxUserInfoResponseSize int64
	stateExpiration         time.Duration
	stateCleanupInterval    time.Duration
}

// Option configures the OAuth handler.
// Use the With* functions to create Options.
type Option func(*config)

// WithProvider adds an OAuth provider to the handler.
// At least one provider must be specified.
//
// For convenience, use WithGoogle or WithFacebook instead of this function
// with GoogleProviderConfig or FacebookProviderConfig.
//
// Example:
//
//	handler := oauth.New(loginHandler, errorHandler,
//	    oauth.WithProvider(customProviderConfig),
//	)
func WithProvider(p *ProviderConfig) Option {
	return func(c *config) {
		c.providers = append(c.providers, p)
	}
}

// WithMaxUserInfoResponseSize sets the maximum size of the user info response body.
// This limit prevents memory exhaustion from malicious or malformed responses.
// Default is 1MB (DefaultMaxUserInfoResponseSize).
//
// Example:
//
//	handler := oauth.New(loginHandler, errorHandler,
//	    oauth.WithMaxUserInfoResponseSize(2 << 20), // 2MB
//	    oauth.WithProvider(googleConfig),
//	)
func WithMaxUserInfoResponseSize(size int64) Option {
	return func(c *config) {
		c.maxUserInfoResponseSize = size
	}
}

// WithStateExpiration sets how long OAuth states remain valid before expiring.
// States not used within this duration will be considered invalid and rejected.
// Default is 10 minutes (DefaultStateExpiration).
//
// Example:
//
//	handler := oauth.New(loginHandler, errorHandler,
//	    oauth.WithStateExpiration(5 * time.Minute),
//	    oauth.WithProvider(googleConfig),
//	)
func WithStateExpiration(d time.Duration) Option {
	return func(c *config) {
		c.stateExpiration = d
	}
}

// WithStateCleanupInterval sets how often the background goroutine runs to
// clean up expired OAuth states from memory. A shorter interval uses more CPU
// but frees memory faster. Default is 10 minutes (DefaultStateCleanupInterval).
//
// Example:
//
//	handler := oauth.New(loginHandler, errorHandler,
//	    oauth.WithStateCleanupInterval(1 * time.Minute),
//	    oauth.WithProvider(googleConfig),
//	)
func WithStateCleanupInterval(d time.Duration) Option {
	return func(c *config) {
		c.stateCleanupInterval = d
	}
}

// WithGoogle adds Google as an OAuth provider.
// This is a convenience function equivalent to WithProvider(GoogleProviderConfig(...)).
//
// Parameters:
//   - clientId: The Google Client ID from the Google Cloud Console
//   - clientSecret: The Google Client Secret from the Google Cloud Console
//   - callback: The full URL where Google should redirect after authentication
//
// Example:
//
//	handler := oauth.New(loginHandler, errorHandler,
//	    oauth.WithGoogle("your-client-id", "your-client-secret", "https://example.com/auth/google/callback"),
//	)
func WithGoogle(clientId, clientSecret, callback string) Option {
	return WithProvider(GoogleProviderConfig(clientId, clientSecret, callback))
}

// WithFacebook adds Facebook as an OAuth provider.
// This is a convenience function equivalent to WithProvider(FacebookProviderConfig(...)).
//
// Parameters:
//   - appId: The Facebook App ID from the Facebook Developer Console
//   - appSecret: The Facebook App Secret from the Facebook Developer Console
//   - callback: The full URL where Facebook should redirect after authentication
//
// Example:
//
//	handler := oauth.New(loginHandler, errorHandler,
//	    oauth.WithFacebook("your-app-id", "your-app-secret", "https://example.com/auth/facebook/callback"),
//	)
func WithFacebook(appId, appSecret, callback string) Option {
	return WithProvider(FacebookProviderConfig(appId, appSecret, callback))
}

const (
	// ProviderFacebook is the provider type for Facebook OAuth.
	ProviderFacebook ProviderType = "facebook"

	// ProviderGoogle is the provider type for Google OAuth.
	ProviderGoogle ProviderType = "google"
)

// contextKey is used to store values in context without key collisions.
type contextKey int

const (
	userContextKey contextKey = iota
	errorContextKey
)

// newUserContext returns a new context with the user value attached.
func newUserContext(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, userContextKey, u)
}

// FromUserContext extracts the authenticated User from the context.
// This should be called in the loginHandler to retrieve user information
// after successful OAuth authentication.
//
// Returns the user and true if a user is present in the context,
// or nil and false if no user is found.
func FromUserContext(ctx context.Context) (*User, bool) {
	u, ok := ctx.Value(userContextKey).(*User)
	return u, ok
}

// newErrorContext returns a new context with the error value attached.
func newErrorContext(ctx context.Context, u error) context.Context {
	return context.WithValue(ctx, errorContextKey, u)
}

// FromErrorContext extracts the authentication error from the context.
// This should be called in the errorHandler to retrieve error details
// when OAuth authentication fails.
//
// Returns the error and true if an error is present in the context,
// or nil and false if no error is found.
func FromErrorContext(ctx context.Context) (error, bool) {
	u, ok := ctx.Value(errorContextKey).(error)
	return u, ok
}

// New creates a new HTTP handler that manages OAuth2 authentication flows
// for one or more providers.
//
// The returned handler responds to the following routes for each provider:
//   - GET /{provider} - Initiates the OAuth flow by redirecting to the provider
//   - GET /{provider}/callback - Handles the OAuth callback from the provider
//
// On successful authentication, loginHandler is called with the User available
// via FromUserContext. On failure, errorHandler is called with the error
// available via FromErrorContext.
//
// The handler automatically manages OAuth state for CSRF protection, with states
// expiring after the configured duration. A background goroutine periodically
// cleans up expired states.
//
// Available options:
//   - WithProvider: Add an OAuth provider (required, at least one)
//   - WithMaxUserInfoResponseSize: Set max response body size (default 1MB)
//   - WithStateExpiration: Set state validity duration (default 10 minutes)
//   - WithStateCleanupInterval: Set cleanup frequency (default 10 minutes)
//
// Panics if no providers are specified or if any provider has an empty name.
//
// Example:
//
//	handler := oauth.New(loginHandler, errorHandler,
//	    oauth.WithStateExpiration(5 * time.Minute),
//	    oauth.WithGoogle("id", "secret", "http://localhost/auth/google/callback"),
//	    oauth.WithFacebook("id", "secret", "http://localhost/auth/facebook/callback"),
//	)
//	http.Handle("/auth/", http.StripPrefix("/auth", handler))
func New(loginHandler http.Handler, errorHandler http.Handler, opts ...Option) http.Handler {
	cfg := &config{
		maxUserInfoResponseSize: DefaultMaxUserInfoResponseSize,
		stateExpiration:         DefaultStateExpiration,
		stateCleanupInterval:    DefaultStateCleanupInterval,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	if len(cfg.providers) == 0 {
		panic("no providers: use WithProvider to add at least one provider")
	}

	mu := new(sync.RWMutex)
	oauthStates := make(map[string]*oauthState)

	// Start cleanup goroutine for expired states
	go func() {
		ticker := time.NewTicker(cfg.stateCleanupInterval)
		defer ticker.Stop()
		for range ticker.C {
			mu.Lock()
			now := time.Now()
			for state, data := range oauthStates {
				if now.Sub(data.createdAt) > cfg.stateExpiration {
					delete(oauthStates, state)
				}
			}
			mu.Unlock()
		}
	}()

	r := http.NewServeMux()

	for _, providerCfg := range cfg.providers {
		providerCfg := providerCfg // capture loop variable for Go < 1.22
		providerName := string(providerCfg.Provider)
		if providerName == "" {
			panic("no provider name")
		}

		r.HandleFunc("/"+providerName, func(w http.ResponseWriter, r *http.Request) {
			state, err := generateRandomString(16)
			if err != nil {
				errorHandler.ServeHTTP(w, r.WithContext(newErrorContext(r.Context(), fmt.Errorf("failed to generate state: %w", err))))
				return
			}
			mu.Lock()
			oauthStates[state] = &oauthState{
				redirectLink: r.Referer(),
				provider:     providerName,
				createdAt:    time.Now(),
			}
			mu.Unlock()
			http.Redirect(w, r, providerCfg.AuthCodeURL(state), http.StatusTemporaryRedirect)
		})

		r.HandleFunc("/"+providerName+"/callback", func(w http.ResponseWriter, r *http.Request) {
			state := r.URL.Query().Get("state")
			code := r.URL.Query().Get("code")
			mu.RLock()
			oauthState, ok := oauthStates[state]
			mu.RUnlock()
			if !ok || oauthState.provider != providerName {
				errorHandler.ServeHTTP(w, r.WithContext(newErrorContext(r.Context(), fmt.Errorf("invalid state: %s", state))))
				return
			}

			// Check if state has expired
			if time.Since(oauthState.createdAt) > cfg.stateExpiration {
				mu.Lock()
				delete(oauthStates, state)
				mu.Unlock()
				errorHandler.ServeHTTP(w, r.WithContext(newErrorContext(r.Context(), fmt.Errorf("state expired: %s", state))))
				return
			}

			mu.Lock()
			delete(oauthStates, state)
			mu.Unlock()

			token, err := providerCfg.Exchange(r.Context(), code)
			if err != nil {
				errorHandler.ServeHTTP(w, r.WithContext(newErrorContext(r.Context(), err)))
				return
			}

			client := providerCfg.Client(r.Context(), token)

			userInfoResp, err := client.Get(fmt.Sprintf(providerCfg.InfoEndpoint, token.AccessToken))
			if err != nil {
				errorHandler.ServeHTTP(w, r.WithContext(newErrorContext(r.Context(), err)))
				return
			}

			defer userInfoResp.Body.Close()

			// Limit response body size to prevent memory exhaustion
			limitedBody := io.LimitReader(userInfoResp.Body, cfg.maxUserInfoResponseSize)

			user, err := providerCfg.Unmarshal(limitedBody)
			if err != nil {
				errorHandler.ServeHTTP(w, r.WithContext(newErrorContext(r.Context(), err)))
				return
			}
			loginHandler.ServeHTTP(w, r.WithContext(newUserContext(r.Context(), user)))
		})
	}
	return r
}

// generateRandomString generates a cryptographically secure random string
// of the specified size (in bytes). The returned string is hex-encoded,
// so its length will be 2*size characters.
func generateRandomString(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}
