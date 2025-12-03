# go-oauth2-handlers

A lightweight Go package that provides HTTP handlers for OAuth2 authentication with popular providers like Google and Facebook.

## Features

- Simple, handler-based API that integrates with `net/http`
- Built-in support for Google and Facebook OAuth2
- Extensible design for adding custom providers
- Secure state management with automatic expiration
- Context-based user and error passing
- Thread-safe concurrent request handling
- Configurable timeouts and limits

## Installation

```bash
go get github.com/abdullah2993/go-oauth2-handlers/v2
```

## Quick Start

```go
package main

import (
    "fmt"
    "net/http"

    oauth "github.com/abdullah2993/go-oauth2-handlers/v2"
)

func main() {
    // Define handlers for successful login and errors
    loginHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        user, ok := oauth.FromUserContext(r.Context())
        if !ok {
            http.Error(w, "No user in context", http.StatusInternalServerError)
            return
        }
        fmt.Fprintf(w, "Welcome, %s! (Email: %s)", user.Name, user.Email)
    })

    errorHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        err, _ := oauth.FromErrorContext(r.Context())
        http.Error(w, fmt.Sprintf("Authentication failed: %v", err), http.StatusUnauthorized)
    })

    // Create the OAuth handler with providers
    authHandler := oauth.New(loginHandler, errorHandler,
        oauth.WithGoogle(
            "your-google-client-id",
            "your-google-client-secret",
            "http://localhost:8080/auth/google/callback",
        ),
        oauth.WithFacebook(
            "your-facebook-app-id",
            "your-facebook-app-secret",
            "http://localhost:8080/auth/facebook/callback",
        ),
    )

    // Mount the handler
    http.Handle("/auth/", http.StripPrefix("/auth", authHandler))

    fmt.Println("Server starting on :8080")
    http.ListenAndServe(":8080", nil)
}
```

## Usage

### Initiating OAuth Flow

Direct users to the provider-specific endpoint to start the OAuth flow:

- **Google**: `/auth/google`
- **Facebook**: `/auth/facebook`

The user will be redirected to the provider's login page, and upon successful authentication, redirected back to the callback URL.

### Handling Authentication Results

#### Successful Login

On successful authentication, the `loginHandler` receives the request with user information in the context:

```go
loginHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    user, ok := oauth.FromUserContext(r.Context())
    if !ok {
        // Handle missing user (shouldn't happen in loginHandler)
        return
    }

    // Access user information
    fmt.Println("User ID:", user.ID)
    fmt.Println("Name:", user.Name)
    fmt.Println("Email:", user.Email)
    fmt.Println("Avatar:", user.Avatar)
    fmt.Println("Provider:", user.Provider)
})
```

#### Error Handling

On authentication failure, the `errorHandler` receives the request with error information in the context:

```go
errorHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    err, ok := oauth.FromErrorContext(r.Context())
    if !ok {
        http.Error(w, "Unknown error", http.StatusInternalServerError)
        return
    }

    // Log and handle the error
    log.Printf("OAuth error: %v", err)
    http.Error(w, "Authentication failed", http.StatusUnauthorized)
})
```

### User Struct

The `User` struct contains normalized user information from any provider:

```go
type User struct {
    ID        string       // Provider-specific user ID
    Name      string       // Full name
    FirstName string       // First/given name
    LastName  string       // Last/family name
    Email     string       // Email address
    Avatar    string       // Profile picture URL
    Provider  ProviderType // Provider identifier (e.g., "google", "facebook")
}
```

### Custom Providers

You can create custom provider configurations:

```go
customProvider := &oauth.ProviderConfig{
    Provider:     oauth.ProviderType("custom"),
    InfoEndpoint: "https://api.custom.com/userinfo?access_token=%s",
    Config: &oauth2.Config{
        ClientID:     "your-client-id",
        ClientSecret: "your-client-secret",
        Endpoint: oauth2.Endpoint{
            AuthURL:  "https://custom.com/oauth/authorize",
            TokenURL: "https://custom.com/oauth/token",
        },
        RedirectURL: "http://localhost:8080/auth/custom/callback",
        Scopes:      []string{"profile", "email"},
    },
    Unmarshal: func(r io.Reader) (*oauth.User, error) {
        // Parse provider-specific response into User struct
        var data struct {
            ID    string `json:"id"`
            Email string `json:"email"`
            Name  string `json:"name"`
        }
        if err := json.NewDecoder(r).Decode(&data); err != nil {
            return nil, err
        }
        return &oauth.User{
            ID:       data.ID,
            Email:    data.Email,
            Name:     data.Name,
            Provider: "custom",
        }, nil
    },
}
```

## Configuration

### Configuration Options

The `New` function accepts options using the functional options pattern. All configuration is done through `Option` functions, providing compile-time type safety:

```go
authHandler := oauth.New(
    loginHandler,
    errorHandler,
    oauth.WithGoogle("client-id", "secret", "callback"),    // Add Google
    oauth.WithFacebook("app-id", "secret", "callback"),     // Add Facebook
    oauth.WithStateExpiration(5 * time.Minute),             // Custom state expiration
    oauth.WithStateCleanupInterval(1 * time.Minute),        // Custom cleanup interval
    oauth.WithMaxUserInfoResponseSize(2 << 20),             // 2MB limit
)
```

### Available Options

| Option | Description |
|--------|-------------|
| `WithGoogle(clientId, clientSecret, callback)` | Add Google as OAuth provider |
| `WithFacebook(appId, appSecret, callback)` | Add Facebook as OAuth provider |
| `WithProvider(p *ProviderConfig)` | Add a custom OAuth provider |
| `WithMaxUserInfoResponseSize(size int64)` | Max response body size (default 1MB) |
| `WithStateExpiration(d time.Duration)` | State validity duration (default 10min) |
| `WithStateCleanupInterval(d time.Duration)` | Cleanup frequency (default 10min) |

### Default Constants

The package also exports default values as constants for reference:

```go
const (
    DefaultMaxUserInfoResponseSize int64 = 1 << 20        // 1MB
    DefaultStateExpiration         = 10 * time.Minute
    DefaultStateCleanupInterval    = 10 * time.Minute
)
```

### Provider-Specific Scopes

**Google** requests these scopes by default:
- `https://www.googleapis.com/auth/userinfo.email`
- `https://www.googleapis.com/auth/userinfo.profile`

**Facebook** requests these scopes by default:
- `email`

## Security Features

- **CSRF Protection**: Cryptographically random state parameter for each OAuth flow
- **State Expiration**: States automatically expire (configurable, default 10 minutes)
- **One-Time States**: Each state can only be used once
- **Response Size Limits**: User info responses are limited to prevent memory exhaustion
- **Context Propagation**: Request context is properly propagated for timeout/cancellation support

## API Reference

### Functions

#### `New(loginHandler, errorHandler http.Handler, opts ...Option) http.Handler`

Creates a new OAuth handler multiplexer.

- `loginHandler`: Called on successful authentication with user in context
- `errorHandler`: Called on authentication failure with error in context
- `opts`: Configuration options (use `WithProvider` to add providers)

Panics if no providers are specified (at least one `WithProvider` is required).

#### `FromUserContext(ctx context.Context) (*User, bool)`

Extracts the authenticated user from the request context.

#### `FromErrorContext(ctx context.Context) (error, bool)`

Extracts the authentication error from the request context.

#### `GoogleProviderConfig(appId, appSecret, callback string) *ProviderConfig`

Creates a Google OAuth2 provider configuration.

#### `FacebookProviderConfig(appId, appSecret, callback string) *ProviderConfig`

Creates a Facebook OAuth2 provider configuration.

### Option Functions

#### `WithGoogle(clientId, clientSecret, callback string) Option`

Adds Google as an OAuth provider.

#### `WithFacebook(appId, appSecret, callback string) Option`

Adds Facebook as an OAuth provider.

#### `WithProvider(p *ProviderConfig) Option`

Adds a custom OAuth provider to the handler.

#### `WithMaxUserInfoResponseSize(size int64) Option`

Sets the maximum size of the user info response body.

#### `WithStateExpiration(d time.Duration) Option`

Sets how long OAuth states remain valid.

#### `WithStateCleanupInterval(d time.Duration) Option`

Sets how often expired states are cleaned up.

## Example: Full Web Application

```go
package main

import (
    "encoding/json"
    "fmt"
    "html/template"
    "net/http"
    "time"

    oauth "github.com/abdullah2993/go-oauth2-handlers/v2"
)

var tmpl = template.Must(template.New("home").Parse(`
<!DOCTYPE html>
<html>
<head><title>OAuth Demo</title></head>
<body>
    <h1>Login</h1>
    <a href="/auth/google">Login with Google</a><br>
    <a href="/auth/facebook">Login with Facebook</a>
</body>
</html>
`))

func main() {
    // Home page
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        tmpl.Execute(w, nil)
    })

    // Success handler - create session and redirect
    loginHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        user, _ := oauth.FromUserContext(r.Context())

        // In a real app: create session, store user, etc.
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(user)
    })

    // Error handler
    errorHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        err, _ := oauth.FromErrorContext(r.Context())
        http.Error(w, err.Error(), http.StatusUnauthorized)
    })

    // Setup OAuth with custom configuration
    authHandler := oauth.New(
        loginHandler,
        errorHandler,
        oauth.WithStateExpiration(5 * time.Minute),
        oauth.WithMaxUserInfoResponseSize(2 << 20), // 2MB
        oauth.WithGoogle(
            "GOOGLE_CLIENT_ID",
            "GOOGLE_CLIENT_SECRET",
            "http://localhost:8080/auth/google/callback",
        ),
    )

    http.Handle("/auth/", http.StripPrefix("/auth", authHandler))

    fmt.Println("Server running at http://localhost:8080")
    http.ListenAndServe(":8080", nil)
}
```

## License

MIT License - see [LICENSE](LICENSE) for details.
