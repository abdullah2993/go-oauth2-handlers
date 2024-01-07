package oauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sync"

	"golang.org/x/oauth2"
)

type User struct {
	ID        string
	Name      string
	FirstName string
	LastName  string
	Email     string
	Avatar    string
	Provider  ProviderType
}

type ProviderType string

type oauthState struct {
	redirectLink string
	provider     string
}

type ProviderConfig struct {
	Provider ProviderType
	*oauth2.Config
	InfoEndpoint string
	Unmarshal    func(r io.Reader) (*User, error)
}

const (
	ProviderFacebook ProviderType = "facebook"
	ProviderGoogle   ProviderType = "google"
)

type contextKey int

const (
	userContextKey contextKey = iota
	errorContextKey
)

func newUserContext(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, userContextKey, u)
}

func FromUserContext(ctx context.Context) (*User, bool) {
	u, ok := ctx.Value(userContextKey).(*User)
	return u, ok
}

func newErrorContext(ctx context.Context, u error) context.Context {
	return context.WithValue(ctx, errorContextKey, u)
}

func FromErrorContext(ctx context.Context) (error, bool) {
	u, ok := ctx.Value(errorContextKey).(error)
	return u, ok
}

func New(loginHandler http.Handler, errorHandler http.Handler, providers ...*ProviderConfig) http.Handler {
	if len(providers) == 0 {
		panic("no providers")
	}

	mu := new(sync.RWMutex)
	oauthStates := make(map[string]*oauthState)

	r := http.NewServeMux()

	for _, config := range providers {
		providerName := string(config.Provider)
		if providerName == "" {
			panic("no provider name")
		}

		r.HandleFunc("/"+providerName, func(w http.ResponseWriter, r *http.Request) {
			state := generateRandomString(16)
			mu.Lock()
			oauthStates[state] = &oauthState{
				redirectLink: r.Referer(),
				provider:     providerName,
			}
			mu.Unlock()
			http.Redirect(w, r, config.AuthCodeURL(state), http.StatusTemporaryRedirect)
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
			mu.Lock()
			delete(oauthStates, state)
			mu.Unlock()

			token, err := config.Exchange(context.Background(), code)
			if err != nil {
				errorHandler.ServeHTTP(w, r.WithContext(newErrorContext(r.Context(), err)))
				return
			}

			// TODO context option?
			client := config.Client(context.Background(), token)

			userInfoResp, err := client.Get(fmt.Sprintf(config.InfoEndpoint, token.AccessToken))
			if err != nil {
				errorHandler.ServeHTTP(w, r.WithContext(newErrorContext(r.Context(), err)))
				return
			}

			defer userInfoResp.Body.Close()

			user, err := config.Unmarshal(userInfoResp.Body)
			if err != nil {
				errorHandler.ServeHTTP(w, r.WithContext(newErrorContext(r.Context(), err)))
				return
			}
			loginHandler.ServeHTTP(w, r.WithContext(newUserContext(r.Context(), user)))
		})
	}
	return r
}

func generateRandomString(size int) string {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return hex.EncodeToString(b)
}
