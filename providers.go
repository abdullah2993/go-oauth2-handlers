package oauth

import (
	"encoding/json"
	"io"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/google"
)

func FacebookProviderConfig(appId, appSecret, callback string) *OAuthProviderConfig {
	return &OAuthProviderConfig{
		InfoEndpoint: "https://graph.facebook.com/me?fields=email,first_name,last_name,link,about,id,name,picture,location&access_token=%s",
		Config: &oauth2.Config{
			ClientID:     appId,
			ClientSecret: appSecret,
			Endpoint:     facebook.Endpoint,
			RedirectURL:  callback,
			Scopes:       []string{"email"},
		},
		Unmarshal: func(r io.Reader) (*OAuthUser, error) {

			rawInfo := struct {
				ID        string `json:"id"`
				Email     string `json:"email"`
				FirstName string `json:"first_name"`
				LastName  string `json:"last_name"`
				Name      string `json:"name"`
				Picture   struct {
					Data struct {
						Height       int    `json:"height"`
						IsSilhouette bool   `json:"is_silhouette"`
						URL          string `json:"url"`
						Width        int    `json:"width"`
					} `json:"data"`
				} `json:"picture"`
			}{}

			jsonDecoder := json.NewDecoder(r)
			if err := jsonDecoder.Decode(&rawInfo); err != nil {
				return nil, err
			}

			return &OAuthUser{
				ID:        rawInfo.ID,
				FirstName: rawInfo.FirstName,
				LastName:  rawInfo.LastName,
				Avatar:    rawInfo.Picture.Data.URL,
				Email:     rawInfo.Email,
				Provider:  ProviderFacebook,
			}, nil
		},
	}
}

func GoogleProivderConfig(appId, appSecret, callback string) *OAuthProviderConfig {
	return &OAuthProviderConfig{
		InfoEndpoint: "https://www.googleapis.com/oauth2/v2/userinfo?access_token=%s",
		Config: &oauth2.Config{
			ClientID:     appId,
			ClientSecret: appSecret,
			Endpoint:     google.Endpoint,
			RedirectURL:  callback,
			Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
		},
		Unmarshal: func(r io.Reader) (*OAuthUser, error) {

			rawInfo := struct {
				ID            string `json:"id"`
				Email         string `json:"email"`
				VerifiedEmail bool   `json:"verified_email"`
				Name          string `json:"name"`
				GivenName     string `json:"given_name"`
				FamilyName    string `json:"family_name"`
				Picture       string `json:"picture"`
				Locale        string `json:"locale"`
			}{}

			jsonDecoder := json.NewDecoder(r)
			if err := jsonDecoder.Decode(&rawInfo); err != nil {
				return nil, err
			}

			return &OAuthUser{
				ID:        rawInfo.ID,
				FirstName: rawInfo.GivenName,
				LastName:  rawInfo.FamilyName,
				Avatar:    rawInfo.Picture,
				Email:     rawInfo.Email,
				Provider:  ProviderGoogle,
			}, nil
		},
	}
}
