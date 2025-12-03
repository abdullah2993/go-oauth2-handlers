package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// mockProviderConfig creates a test provider configuration
func mockProviderConfig(name ProviderType, authServer *httptest.Server) *ProviderConfig {
	return &ProviderConfig{
		Provider:     name,
		InfoEndpoint: authServer.URL + "/userinfo?access_token=%s",
		Config: &oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			Endpoint: oauth2.Endpoint{
				AuthURL:  authServer.URL + "/auth",
				TokenURL: authServer.URL + "/token",
			},
			RedirectURL: "http://localhost/callback",
			Scopes:      []string{"email", "profile"},
		},
		Unmarshal: func(r io.Reader) (*User, error) {
			var user User
			if err := json.NewDecoder(r).Decode(&user); err != nil {
				return nil, err
			}
			user.Provider = name
			return &user, nil
		},
	}
}

func TestFromUserContext(t *testing.T) {
	t.Run("returns user when present", func(t *testing.T) {
		user := &User{
			ID:    "123",
			Name:  "Test User",
			Email: "test@example.com",
		}
		ctx := newUserContext(context.Background(), user)

		got, ok := FromUserContext(ctx)
		if !ok {
			t.Fatal("expected user to be present in context")
		}
		if got.ID != user.ID {
			t.Errorf("got ID %q, want %q", got.ID, user.ID)
		}
		if got.Email != user.Email {
			t.Errorf("got Email %q, want %q", got.Email, user.Email)
		}
	})

	t.Run("returns false when user not present", func(t *testing.T) {
		ctx := context.Background()

		_, ok := FromUserContext(ctx)
		if ok {
			t.Error("expected user to not be present in context")
		}
	})
}

func TestFromErrorContext(t *testing.T) {
	t.Run("returns error when present", func(t *testing.T) {
		expectedErr := errors.New("test error")
		ctx := newErrorContext(context.Background(), expectedErr)

		got, ok := FromErrorContext(ctx)
		if !ok {
			t.Fatal("expected error to be present in context")
		}
		if got.Error() != expectedErr.Error() {
			t.Errorf("got error %q, want %q", got.Error(), expectedErr.Error())
		}
	})

	t.Run("returns false when error not present", func(t *testing.T) {
		ctx := context.Background()

		_, ok := FromErrorContext(ctx)
		if ok {
			t.Error("expected error to not be present in context")
		}
	})
}

func TestNew_PanicsWithNoProviders(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic with no providers")
		}
	}()

	New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
}

func TestNew_PanicsWithEmptyProviderName(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic with empty provider name")
		}
	}()

	providerConfig := &ProviderConfig{
		Provider: "", // empty name
		Config: &oauth2.Config{
			ClientID:     "test",
			ClientSecret: "test",
		},
	}

	New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		WithProvider(providerConfig))
}

func TestNew_LoginRedirect(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mock auth server
	}))
	defer authServer.Close()

	providerConfig := mockProviderConfig("testprovider", authServer)

	handler := New(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		WithProvider(providerConfig),
	)

	req := httptest.NewRequest(http.MethodGet, "/testprovider", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusTemporaryRedirect)
	}

	location := rec.Header().Get("Location")
	if !strings.Contains(location, authServer.URL+"/auth") {
		t.Errorf("redirect location %q does not contain auth URL", location)
	}
	if !strings.Contains(location, "state=") {
		t.Errorf("redirect location %q does not contain state parameter", location)
	}
}

func TestNew_CallbackInvalidState(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer authServer.Close()

	providerConfig := mockProviderConfig("testprovider", authServer)

	var errorCalled bool
	errorHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		errorCalled = true
		err, ok := FromErrorContext(r.Context())
		if !ok {
			t.Error("expected error in context")
		}
		if !strings.Contains(err.Error(), "invalid state") {
			t.Errorf("expected 'invalid state' error, got: %v", err)
		}
	})

	handler := New(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		errorHandler,
		WithProvider(providerConfig),
	)

	req := httptest.NewRequest(http.MethodGet, "/testprovider/callback?state=invalid&code=testcode", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !errorCalled {
		t.Error("expected error handler to be called")
	}
}

func TestNew_MultipleProviders(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer authServer.Close()

	config1 := mockProviderConfig("provider1", authServer)
	config2 := mockProviderConfig("provider2", authServer)

	handler := New(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		WithProvider(config1),
		WithProvider(config2),
	)

	// Test provider1 endpoint
	req1 := httptest.NewRequest(http.MethodGet, "/provider1", nil)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusTemporaryRedirect {
		t.Errorf("provider1: got status %d, want %d", rec1.Code, http.StatusTemporaryRedirect)
	}

	// Test provider2 endpoint
	req2 := httptest.NewRequest(http.MethodGet, "/provider2", nil)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusTemporaryRedirect {
		t.Errorf("provider2: got status %d, want %d", rec2.Code, http.StatusTemporaryRedirect)
	}
}

func TestGenerateRandomString(t *testing.T) {
	t.Run("generates string of correct length", func(t *testing.T) {
		size := 16
		result, err := generateRandomString(size)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// hex encoding doubles the length
		expectedLen := size * 2
		if len(result) != expectedLen {
			t.Errorf("got length %d, want %d", len(result), expectedLen)
		}
	})

	t.Run("generates unique strings", func(t *testing.T) {
		seen := make(map[string]bool)
		for i := 0; i < 100; i++ {
			result, err := generateRandomString(16)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if seen[result] {
				t.Error("generated duplicate string")
			}
			seen[result] = true
		}
	})
}

func TestNew_FullOAuthFlow(t *testing.T) {
	// Create a mock OAuth server that handles token exchange and userinfo
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth":
			// This would normally redirect to provider's login page
			w.WriteHeader(http.StatusOK)
		case "/token":
			// Return a mock token
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token":  "mock-access-token",
				"token_type":    "Bearer",
				"expires_in":    3600,
				"refresh_token": "mock-refresh-token",
			})
		case "/userinfo":
			// Return mock user info
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(User{
				ID:        "user-123",
				Name:      "Test User",
				FirstName: "Test",
				LastName:  "User",
				Email:     "test@example.com",
				Avatar:    "https://example.com/avatar.png",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer authServer.Close()

	providerConfig := mockProviderConfig("testprovider", authServer)

	var loginCalled bool
	var receivedUser *User

	loginHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loginCalled = true
		user, ok := FromUserContext(r.Context())
		if ok {
			receivedUser = user
		}
		w.WriteHeader(http.StatusOK)
	})

	errorHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err, _ := FromErrorContext(r.Context())
		t.Errorf("unexpected error: %v", err)
	})

	handler := New(loginHandler, errorHandler, WithProvider(providerConfig))

	// Step 1: Initiate OAuth flow
	req1 := httptest.NewRequest(http.MethodGet, "/testprovider", nil)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusTemporaryRedirect {
		t.Fatalf("step 1: got status %d, want %d", rec1.Code, http.StatusTemporaryRedirect)
	}

	// Extract state from redirect URL
	location, err := url.Parse(rec1.Header().Get("Location"))
	if err != nil {
		t.Fatalf("failed to parse redirect URL: %v", err)
	}
	state := location.Query().Get("state")
	if state == "" {
		t.Fatal("no state in redirect URL")
	}

	// Step 2: Simulate callback from OAuth provider
	callbackURL := "/testprovider/callback?state=" + state + "&code=auth-code-123"
	req2 := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if !loginCalled {
		t.Error("login handler was not called")
	}

	if receivedUser == nil {
		t.Fatal("no user received in login handler")
	}

	if receivedUser.ID != "user-123" {
		t.Errorf("got user ID %q, want %q", receivedUser.ID, "user-123")
	}

	if receivedUser.Email != "test@example.com" {
		t.Errorf("got user email %q, want %q", receivedUser.Email, "test@example.com")
	}

	if receivedUser.Provider != "testprovider" {
		t.Errorf("got provider %q, want %q", receivedUser.Provider, "testprovider")
	}
}

func TestNew_StateCannotBeReused(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "mock-access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(User{ID: "user-123", Email: "test@example.com"})
		}
	}))
	defer authServer.Close()

	providerConfig := mockProviderConfig("testprovider", authServer)

	loginHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	var secondCallError error
	errorHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondCallError, _ = FromErrorContext(r.Context())
	})

	handler := New(loginHandler, errorHandler, WithProvider(providerConfig))

	// Step 1: Initiate flow
	req1 := httptest.NewRequest(http.MethodGet, "/testprovider", nil)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	location, _ := url.Parse(rec1.Header().Get("Location"))
	state := location.Query().Get("state")

	// Step 2: First callback (should succeed)
	callbackURL := "/testprovider/callback?state=" + state + "&code=auth-code"
	req2 := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	// Step 3: Try to reuse the same state (should fail)
	req3 := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)

	if secondCallError == nil {
		t.Error("expected error on state reuse")
	}
	if !strings.Contains(secondCallError.Error(), "invalid state") {
		t.Errorf("expected 'invalid state' error, got: %v", secondCallError)
	}
}

func TestUser_Fields(t *testing.T) {
	user := User{
		ID:        "123",
		Name:      "John Doe",
		FirstName: "John",
		LastName:  "Doe",
		Email:     "john@example.com",
		Avatar:    "https://example.com/avatar.jpg",
		Provider:  ProviderGoogle,
	}

	if user.ID != "123" {
		t.Errorf("ID = %q, want %q", user.ID, "123")
	}
	if user.Name != "John Doe" {
		t.Errorf("Name = %q, want %q", user.Name, "John Doe")
	}
	if user.FirstName != "John" {
		t.Errorf("FirstName = %q, want %q", user.FirstName, "John")
	}
	if user.LastName != "Doe" {
		t.Errorf("LastName = %q, want %q", user.LastName, "Doe")
	}
	if user.Email != "john@example.com" {
		t.Errorf("Email = %q, want %q", user.Email, "john@example.com")
	}
	if user.Avatar != "https://example.com/avatar.jpg" {
		t.Errorf("Avatar = %q, want %q", user.Avatar, "https://example.com/avatar.jpg")
	}
	if user.Provider != ProviderGoogle {
		t.Errorf("Provider = %q, want %q", user.Provider, ProviderGoogle)
	}
}

func TestProviderTypes(t *testing.T) {
	if ProviderFacebook != "facebook" {
		t.Errorf("ProviderFacebook = %q, want %q", ProviderFacebook, "facebook")
	}
	if ProviderGoogle != "google" {
		t.Errorf("ProviderGoogle = %q, want %q", ProviderGoogle, "google")
	}
}

func TestNew_WithOptions(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "mock-access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(User{ID: "user-123", Email: "test@example.com"})
		}
	}))
	defer authServer.Close()

	providerConfig := mockProviderConfig("testprovider", authServer)

	t.Run("accepts options before providers", func(t *testing.T) {
		handler := New(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
			WithStateExpiration(5*time.Minute),
			WithStateCleanupInterval(1*time.Minute),
			WithMaxUserInfoResponseSize(2<<20),
			WithProvider(providerConfig),
		)

		req := httptest.NewRequest(http.MethodGet, "/testprovider", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusTemporaryRedirect {
			t.Errorf("got status %d, want %d", rec.Code, http.StatusTemporaryRedirect)
		}
	})

	t.Run("accepts options after providers", func(t *testing.T) {
		handler := New(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
			WithProvider(providerConfig),
			WithStateExpiration(5*time.Minute),
		)

		req := httptest.NewRequest(http.MethodGet, "/testprovider", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusTemporaryRedirect {
			t.Errorf("got status %d, want %d", rec.Code, http.StatusTemporaryRedirect)
		}
	})

	t.Run("accepts mixed options and providers", func(t *testing.T) {
		config2 := mockProviderConfig("provider2", authServer)

		handler := New(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
			WithStateExpiration(5*time.Minute),
			WithProvider(providerConfig),
			WithMaxUserInfoResponseSize(2<<20),
			WithProvider(config2),
		)

		// Test first provider
		req1 := httptest.NewRequest(http.MethodGet, "/testprovider", nil)
		rec1 := httptest.NewRecorder()
		handler.ServeHTTP(rec1, req1)
		if rec1.Code != http.StatusTemporaryRedirect {
			t.Errorf("provider1: got status %d, want %d", rec1.Code, http.StatusTemporaryRedirect)
		}

		// Test second provider
		req2 := httptest.NewRequest(http.MethodGet, "/provider2", nil)
		rec2 := httptest.NewRecorder()
		handler.ServeHTTP(rec2, req2)
		if rec2.Code != http.StatusTemporaryRedirect {
			t.Errorf("provider2: got status %d, want %d", rec2.Code, http.StatusTemporaryRedirect)
		}
	})
}

func TestNew_PanicsWithOnlyOptions(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic with no providers (only options)")
		}
	}()

	New(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		WithStateExpiration(5*time.Minute),
	)
}

func TestDefaultConstants(t *testing.T) {
	if DefaultMaxUserInfoResponseSize != 1<<20 {
		t.Errorf("DefaultMaxUserInfoResponseSize = %d, want %d", DefaultMaxUserInfoResponseSize, 1<<20)
	}
	if DefaultStateExpiration != 10*time.Minute {
		t.Errorf("DefaultStateExpiration = %v, want %v", DefaultStateExpiration, 10*time.Minute)
	}
	if DefaultStateCleanupInterval != 10*time.Minute {
		t.Errorf("DefaultStateCleanupInterval = %v, want %v", DefaultStateCleanupInterval, 10*time.Minute)
	}
}

func TestOptions(t *testing.T) {
	t.Run("WithMaxUserInfoResponseSize", func(t *testing.T) {
		cfg := &config{}
		opt := WithMaxUserInfoResponseSize(2 << 20)
		opt(cfg)
		if cfg.maxUserInfoResponseSize != 2<<20 {
			t.Errorf("got %d, want %d", cfg.maxUserInfoResponseSize, 2<<20)
		}
	})

	t.Run("WithStateExpiration", func(t *testing.T) {
		cfg := &config{}
		opt := WithStateExpiration(5 * time.Minute)
		opt(cfg)
		if cfg.stateExpiration != 5*time.Minute {
			t.Errorf("got %v, want %v", cfg.stateExpiration, 5*time.Minute)
		}
	})

	t.Run("WithStateCleanupInterval", func(t *testing.T) {
		cfg := &config{}
		opt := WithStateCleanupInterval(2 * time.Minute)
		opt(cfg)
		if cfg.stateCleanupInterval != 2*time.Minute {
			t.Errorf("got %v, want %v", cfg.stateCleanupInterval, 2*time.Minute)
		}
	})

	t.Run("WithProvider", func(t *testing.T) {
		cfg := &config{}
		provider := &ProviderConfig{Provider: "test"}
		opt := WithProvider(provider)
		opt(cfg)
		if len(cfg.providers) != 1 {
			t.Errorf("got %d providers, want 1", len(cfg.providers))
		}
		if cfg.providers[0].Provider != "test" {
			t.Errorf("got provider %q, want %q", cfg.providers[0].Provider, "test")
		}
	})

	t.Run("WithGoogle", func(t *testing.T) {
		cfg := &config{}
		opt := WithGoogle("client-id", "client-secret", "callback-url")
		opt(cfg)

		if len(cfg.providers) != 1 {
			t.Fatalf("got %d providers, want 1", len(cfg.providers))
		}

		provider := cfg.providers[0]
		if provider.Provider != ProviderGoogle {
			t.Errorf("Provider = %q, want %q", provider.Provider, ProviderGoogle)
		}
		if provider.ClientID != "client-id" {
			t.Errorf("ClientID = %q, want %q", provider.ClientID, "client-id")
		}
		if provider.ClientSecret != "client-secret" {
			t.Errorf("ClientSecret = %q, want %q", provider.ClientSecret, "client-secret")
		}
		if provider.RedirectURL != "callback-url" {
			t.Errorf("RedirectURL = %q, want %q", provider.RedirectURL, "callback-url")
		}
	})

	t.Run("WithFacebook", func(t *testing.T) {
		cfg := &config{}
		opt := WithFacebook("app-id", "app-secret", "callback-url")
		opt(cfg)

		if len(cfg.providers) != 1 {
			t.Fatalf("got %d providers, want 1", len(cfg.providers))
		}

		provider := cfg.providers[0]
		if provider.Provider != ProviderFacebook {
			t.Errorf("Provider = %q, want %q", provider.Provider, ProviderFacebook)
		}
		if provider.ClientID != "app-id" {
			t.Errorf("ClientID = %q, want %q", provider.ClientID, "app-id")
		}
		if provider.ClientSecret != "app-secret" {
			t.Errorf("ClientSecret = %q, want %q", provider.ClientSecret, "app-secret")
		}
		if provider.RedirectURL != "callback-url" {
			t.Errorf("RedirectURL = %q, want %q", provider.RedirectURL, "callback-url")
		}
	})
}
