package oauth

import (
	"strings"
	"testing"

	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/google"
)

func TestFacebookProviderConfig(t *testing.T) {
	appID := "test-app-id"
	appSecret := "test-app-secret"
	callback := "https://example.com/auth/facebook/callback"

	config := FacebookProviderConfig(appID, appSecret, callback)

	t.Run("sets provider type", func(t *testing.T) {
		if config.Provider != ProviderFacebook {
			t.Errorf("Provider = %q, want %q", config.Provider, ProviderFacebook)
		}
	})

	t.Run("sets OAuth2 config", func(t *testing.T) {
		if config.ClientID != appID {
			t.Errorf("ClientID = %q, want %q", config.ClientID, appID)
		}
		if config.ClientSecret != appSecret {
			t.Errorf("ClientSecret = %q, want %q", config.ClientSecret, appSecret)
		}
		if config.RedirectURL != callback {
			t.Errorf("RedirectURL = %q, want %q", config.RedirectURL, callback)
		}
		if config.Endpoint != facebook.Endpoint {
			t.Error("Endpoint does not match facebook.Endpoint")
		}
	})

	t.Run("sets correct scopes", func(t *testing.T) {
		if len(config.Scopes) != 1 || config.Scopes[0] != "email" {
			t.Errorf("Scopes = %v, want [email]", config.Scopes)
		}
	})

	t.Run("sets info endpoint", func(t *testing.T) {
		if !strings.Contains(config.InfoEndpoint, "graph.facebook.com") {
			t.Errorf("InfoEndpoint %q does not contain graph.facebook.com", config.InfoEndpoint)
		}
	})

	t.Run("unmarshal parses user info", func(t *testing.T) {
		jsonData := `{
			"id": "12345",
			"email": "test@example.com",
			"first_name": "John",
			"last_name": "Doe",
			"name": "John Doe",
			"picture": {
				"data": {
					"url": "https://example.com/photo.jpg",
					"width": 100,
					"height": 100,
					"is_silhouette": false
				}
			}
		}`

		user, err := config.Unmarshal(strings.NewReader(jsonData))
		if err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}

		if user.ID != "12345" {
			t.Errorf("ID = %q, want %q", user.ID, "12345")
		}
		if user.Email != "test@example.com" {
			t.Errorf("Email = %q, want %q", user.Email, "test@example.com")
		}
		if user.FirstName != "John" {
			t.Errorf("FirstName = %q, want %q", user.FirstName, "John")
		}
		if user.LastName != "Doe" {
			t.Errorf("LastName = %q, want %q", user.LastName, "Doe")
		}
		if user.Name != "John Doe" {
			t.Errorf("Name = %q, want %q", user.Name, "John Doe")
		}
		if user.Avatar != "https://example.com/photo.jpg" {
			t.Errorf("Avatar = %q, want %q", user.Avatar, "https://example.com/photo.jpg")
		}
		if user.Provider != ProviderFacebook {
			t.Errorf("Provider = %q, want %q", user.Provider, ProviderFacebook)
		}
	})

	t.Run("unmarshal handles invalid JSON", func(t *testing.T) {
		_, err := config.Unmarshal(strings.NewReader("invalid json"))
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})
}

func TestGoogleProviderConfig(t *testing.T) {
	appID := "test-app-id"
	appSecret := "test-app-secret"
	callback := "https://example.com/auth/google/callback"

	config := GoogleProviderConfig(appID, appSecret, callback)

	t.Run("sets provider type", func(t *testing.T) {
		if config.Provider != ProviderGoogle {
			t.Errorf("Provider = %q, want %q", config.Provider, ProviderGoogle)
		}
	})

	t.Run("sets OAuth2 config", func(t *testing.T) {
		if config.ClientID != appID {
			t.Errorf("ClientID = %q, want %q", config.ClientID, appID)
		}
		if config.ClientSecret != appSecret {
			t.Errorf("ClientSecret = %q, want %q", config.ClientSecret, appSecret)
		}
		if config.RedirectURL != callback {
			t.Errorf("RedirectURL = %q, want %q", config.RedirectURL, callback)
		}
		if config.Endpoint != google.Endpoint {
			t.Error("Endpoint does not match google.Endpoint")
		}
	})

	t.Run("sets correct scopes", func(t *testing.T) {
		expectedScopes := []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		}
		if len(config.Scopes) != len(expectedScopes) {
			t.Fatalf("Scopes length = %d, want %d", len(config.Scopes), len(expectedScopes))
		}
		for i, scope := range expectedScopes {
			if config.Scopes[i] != scope {
				t.Errorf("Scopes[%d] = %q, want %q", i, config.Scopes[i], scope)
			}
		}
	})

	t.Run("sets info endpoint", func(t *testing.T) {
		if !strings.Contains(config.InfoEndpoint, "googleapis.com") {
			t.Errorf("InfoEndpoint %q does not contain googleapis.com", config.InfoEndpoint)
		}
	})

	t.Run("unmarshal parses user info", func(t *testing.T) {
		jsonData := `{
			"id": "67890",
			"email": "user@gmail.com",
			"verified_email": true,
			"name": "Jane Smith",
			"given_name": "Jane",
			"family_name": "Smith",
			"picture": "https://lh3.googleusercontent.com/photo.jpg",
			"locale": "en"
		}`

		user, err := config.Unmarshal(strings.NewReader(jsonData))
		if err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}

		if user.ID != "67890" {
			t.Errorf("ID = %q, want %q", user.ID, "67890")
		}
		if user.Email != "user@gmail.com" {
			t.Errorf("Email = %q, want %q", user.Email, "user@gmail.com")
		}
		if user.FirstName != "Jane" {
			t.Errorf("FirstName = %q, want %q", user.FirstName, "Jane")
		}
		if user.LastName != "Smith" {
			t.Errorf("LastName = %q, want %q", user.LastName, "Smith")
		}
		if user.Name != "Jane Smith" {
			t.Errorf("Name = %q, want %q", user.Name, "Jane Smith")
		}
		if user.Avatar != "https://lh3.googleusercontent.com/photo.jpg" {
			t.Errorf("Avatar = %q, want %q", user.Avatar, "https://lh3.googleusercontent.com/photo.jpg")
		}
		if user.Provider != ProviderGoogle {
			t.Errorf("Provider = %q, want %q", user.Provider, ProviderGoogle)
		}
	})

	t.Run("unmarshal handles invalid JSON", func(t *testing.T) {
		_, err := config.Unmarshal(strings.NewReader("not valid json"))
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})

	t.Run("unmarshal handles empty response", func(t *testing.T) {
		_, err := config.Unmarshal(strings.NewReader(""))
		if err == nil {
			t.Error("expected error for empty response")
		}
	})
}

func TestProviderConfig_InfoEndpointFormat(t *testing.T) {
	t.Run("Facebook endpoint accepts access token", func(t *testing.T) {
		config := FacebookProviderConfig("id", "secret", "callback")
		if !strings.Contains(config.InfoEndpoint, "%s") {
			t.Error("InfoEndpoint should contain placeholder for access token")
		}
	})

	t.Run("Google endpoint accepts access token", func(t *testing.T) {
		config := GoogleProviderConfig("id", "secret", "callback")
		if !strings.Contains(config.InfoEndpoint, "%s") {
			t.Error("InfoEndpoint should contain placeholder for access token")
		}
	})
}
