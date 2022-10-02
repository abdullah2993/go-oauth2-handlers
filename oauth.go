package oauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/gorilla/mux"
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

const (
	ProviderFacebook ProviderType = "facebook"
	ProviderGoogle   ProviderType = "google"
)

type oauthHandler struct {
	oauthProviderConfigs map[string]*OAuthProviderConfig
	loginHandler         OAuthLoginHandler
	errorHandler         OAuthErrorHandler
	handler              http.Handler
	mu                   sync.RWMutex
	oauthStates          map[string]*oauthState
}

func New(loginHandler OAuthLoginHandler, errorHandler OAuthErrorHandler, providers ...*OAuthProviderConfig) http.Handler {
	hand := &oauthHandler{
		loginHandler:         loginHandler,
		errorHandler:         errorHandler,
		oauthStates:          make(map[string]*oauthState),
		oauthProviderConfigs: make(map[string]*OAuthProviderConfig),
	}
	if len(providers) == 0 {
		return nil
	}
	for _, val := range providers {
		hand.oauthProviderConfigs[string(val.Provider)] = val
	}
	r := mux.NewRouter()
	r.Path("/callback").Methods("GET").Queries("code", "{code}", "state", "{state}").HandlerFunc(hand.handleEnd)
	r.Path("/{provider}").Methods("GET").HandlerFunc(hand.handleBegin)
	hand.handler = r
	return hand
}

func (h *oauthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.handler.ServeHTTP(w, r)
}

func (h *oauthHandler) handleOauth(w http.ResponseWriter, r *http.Request) error {
	vars := mux.Vars(r)
	provider := vars["provider"]

	oauthConf, ok := h.oauthProviderConfigs[provider]
	if !ok {
		return fmt.Errorf("invalid provider: %s", provider)
	}

	oauthState := h.newOauthState(r, provider)

	http.Redirect(w, r, oauthConf.AuthCodeURL(oauthState), http.StatusTemporaryRedirect)

	return nil
}

func (h *oauthHandler) handleOauthCallback(w http.ResponseWriter, r *http.Request) (*OAuthUser, error) {
	vars := mux.Vars(r)
	state := vars["state"]
	code := vars["code"]
	h.mu.RLock()
	oauthState, ok := h.oauthStates[state]
	h.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("invalid state: %s", state)
	}
	h.mu.Lock()
	delete(h.oauthStates, state)
	h.mu.Unlock()
	providerConf, ok := h.oauthProviderConfigs[oauthState.provider]
	if !ok {
		return nil, fmt.Errorf("invalid provider: %s", state)
	}

	token, err := providerConf.Exchange(context.Background(), code)
	if err != nil {
		return nil, err
	}

	client := providerConf.Client(context.Background(), token)

	userInfoResp, err := client.Get(fmt.Sprintf(providerConf.InfoEndpoint, token.AccessToken))
	if err != nil {
		return nil, err
	}

	defer userInfoResp.Body.Close()

	return providerConf.Unmarshal(userInfoResp.Body)
}

func (h *oauthHandler) newOauthState(r *http.Request, provider string) string {
	state := generateRandomString(16)
	h.mu.Lock()
	h.oauthStates[state] = &oauthState{
		redirectLink: r.Referer(),
		provider:     provider,
	}
	h.mu.Unlock()
	return state
}

func (h *oauthHandler) handleBegin(w http.ResponseWriter, r *http.Request) {
	err := h.handleOauth(w, r)
	if err != nil {
		h.errorHandler(w, err)
	}
}
func (h *oauthHandler) handleEnd(w http.ResponseWriter, r *http.Request) {
	user, err := h.handleOauthCallback(w, r)
	if err != nil {
		h.errorHandler(w, err)
		return
	}
	h.loginHandler(w, user)
}

type OAuthLoginHandler func(w http.ResponseWriter, user *OAuthUser)

type OAuthErrorHandler func(w http.ResponseWriter, err error)

func generateRandomString(size int) string {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return hex.EncodeToString(b)
}
