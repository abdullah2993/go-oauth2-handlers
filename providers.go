package oauth

import (
	"encoding/json"
	"io"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/google"
)

// FacebookProviderConfig creates a ProviderConfig for Facebook OAuth2 authentication.
//
// Parameters:
//   - appId: The Facebook App ID from the Facebook Developer Console
//   - appSecret: The Facebook App Secret from the Facebook Developer Console
//   - callback: The full URL where Facebook should redirect after authentication
//     (must match the redirect URI configured in Facebook Developer Console)
//
// The configuration requests the "email" scope and retrieves the following user
// information: id, email, first_name, last_name, name, and profile picture.
//
// For direct use with New(), prefer WithFacebook instead.
func FacebookProviderConfig(appId, appSecret, callback string) *ProviderConfig {
	return &ProviderConfig{
		Provider:     ProviderFacebook,
		InfoEndpoint: "https://graph.facebook.com/me?fields=email,first_name,last_name,link,about,id,name,picture,location&access_token=%s",
		Config: &oauth2.Config{
			ClientID:     appId,
			ClientSecret: appSecret,
			Endpoint:     facebook.Endpoint,
			RedirectURL:  callback,
			Scopes:       []string{"email"},
		},
		Unmarshal: unmarshalFacebookUser,
	}
}

// unmarshalFacebookUser parses Facebook's user info response into a User struct.
func unmarshalFacebookUser(r io.Reader) (*User, error) {
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

	if err := json.NewDecoder(r).Decode(&rawInfo); err != nil {
		return nil, err
	}

	return &User{
		ID:        rawInfo.ID,
		FirstName: rawInfo.FirstName,
		LastName:  rawInfo.LastName,
		Avatar:    rawInfo.Picture.Data.URL,
		Email:     rawInfo.Email,
		Name:      rawInfo.Name,
		Provider:  ProviderFacebook,
	}, nil
}

// GoogleProviderConfig creates a ProviderConfig for Google OAuth2 authentication.
//
// Parameters:
//   - appId: The Google Client ID from the Google Cloud Console
//   - appSecret: The Google Client Secret from the Google Cloud Console
//   - callback: The full URL where Google should redirect after authentication
//     (must match the redirect URI configured in Google Cloud Console)
//
// The configuration requests the following scopes:
//   - https://www.googleapis.com/auth/userinfo.email
//   - https://www.googleapis.com/auth/userinfo.profile
//
// It retrieves the following user information: id, email, verified_email, name,
// given_name, family_name, picture, and locale.
//
// For direct use with New(), prefer WithGoogle instead.
func GoogleProviderConfig(appId, appSecret, callback string) *ProviderConfig {
	return &ProviderConfig{
		Provider:     ProviderGoogle,
		InfoEndpoint: "https://www.googleapis.com/oauth2/v2/userinfo?access_token=%s",
		Config: &oauth2.Config{
			ClientID:     appId,
			ClientSecret: appSecret,
			Endpoint:     google.Endpoint,
			RedirectURL:  callback,
			Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
		},
		Unmarshal: unmarshalGoogleUser,
	}
}

// unmarshalGoogleUser parses Google's user info response into a User struct.
func unmarshalGoogleUser(r io.Reader) (*User, error) {
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

	if err := json.NewDecoder(r).Decode(&rawInfo); err != nil {
		return nil, err
	}

	return &User{
		ID:        rawInfo.ID,
		FirstName: rawInfo.GivenName,
		LastName:  rawInfo.FamilyName,
		Avatar:    rawInfo.Picture,
		Email:     rawInfo.Email,
		Name:      rawInfo.Name,
		Provider:  ProviderGoogle,
	}, nil
}
