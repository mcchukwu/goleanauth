package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"goleanauth/pkg/config"
)

var googleOAuthConfig *oauth2.Config

func InitOAuth(cfg *config.Config) {
	googleOAuthConfig = &oauth2.Config{
		ClientID:     cfg.GoogleClientID,
		ClientSecret: cfg.GoogleClientSecret,
		RedirectURL:  cfg.GoogleRedirectURL,
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint:     google.Endpoint,
	}
}

func exchangeGoogleCode(ctx context.Context, code string) (OAuthUser, error) {
	token, err := googleOAuthConfig.Exchange(ctx, code)
	if err != nil {
		return OAuthUser{}, fmt.Errorf("google code exchange: %w", err)
	}

	client := googleOAuthConfig.Client(ctx, token)

	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return OAuthUser{}, fmt.Errorf("google userinfo fetch: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return OAuthUser{}, fmt.Errorf("google userinfo read: %w", err)
	}

	if err = json.Unmarshal(body, &googleUserInfo); err != nil {
		return OAuthUser{}, fmt.Errorf("google userinfo parse: %w", err)
	}

	return OAuthUser{
		ProviderID: googleUserInfo.ID,
		Provider:   "google",
		Email:      googleUserInfo.Email,
		FirstName:  googleUserInfo.FirstName,
		LastName:   googleUserInfo.LastName,
	}, nil
}
