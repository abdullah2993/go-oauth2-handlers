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

type OAuthUser struct {
	ID        string
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

type OAuthProviderConfig struct {
	Provider ProviderType
	*oauth2.Config
	InfoEndpoint string
	Unmarshal    func(r io.Reader) (*OAuthUser, error)
}

type OAuthLoginHandler func(w http.ResponseWriter, user *OAuthUser)

type OAuthErrorHandler func(w http.ResponseWriter, err error)

const (
	ProviderFacebook ProviderType = "facebook"
	ProviderGoogle   ProviderType = "google"
)

func New(loginHandler OAuthLoginHandler, errorHandler OAuthErrorHandler, providers ...*OAuthProviderConfig) http.Handler {
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
				errorHandler(w, fmt.Errorf("invalid state: %s", state))
				return
			}
			mu.Lock()
			delete(oauthStates, state)
			mu.Unlock()

			token, err := config.Exchange(context.Background(), code)
			if err != nil {
				errorHandler(w, err)
				return
			}

			// TODO context option?
			client := config.Client(context.Background(), token)

			userInfoResp, err := client.Get(fmt.Sprintf(config.InfoEndpoint, token.AccessToken))
			if err != nil {
				errorHandler(w, err)
				return
			}

			defer userInfoResp.Body.Close()

			user, err := config.Unmarshal(userInfoResp.Body)
			if err != nil {
				errorHandler(w, err)
				return
			}
			loginHandler(w, user)
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
