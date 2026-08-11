// Package pages provides the small, self-hosted HTML pages used by the
// interactive OAuth authorization flow: login, consent, and error screens.
package pages

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
)

//go:embed *.html
var files embed.FS

var templates = template.Must(template.ParseFS(files, "*.html"))

// LoginData is the login page form.
type LoginData struct {
	Next  string
	Error string
}

// ConsentData is the OAuth consent screen.
type ConsentData struct {
	ClientName          string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Scopes              []ScopeDetail
}

// ScopeDetail describes a scope for display on the consent screen.
type ScopeDetail struct {
	Name        string
	Description string
}

// OAuthErrorData is the error page shown when a request is invalid and cannot
// be safely redirected (e.g. unknown client or unregistered redirect URI).
type OAuthErrorData struct {
	Code        string
	Description string
}

func render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// Login renders the login page.
func Login(w http.ResponseWriter, data LoginData) {
	render(w, "login.html", data)
}

// Consent renders the OAuth consent screen.
func Consent(w http.ResponseWriter, data ConsentData) {
	render(w, "consent.html", data)
}

// OAuthError renders the generic OAuth error page.
func OAuthError(w http.ResponseWriter, data OAuthErrorData) {
	render(w, "oauth_error.html", data)
}

// ScopeDescriptions returns human-readable descriptions for standard scopes.
func ScopeDescriptions(scopes []string) []ScopeDetail {
	descriptions := map[string]string{
		"openid":  "Verify your identity",
		"profile": "View your basic profile information",
		"email":   "View your email address",
	}
	out := make([]ScopeDetail, 0, len(scopes))
	for _, s := range scopes {
		desc, ok := descriptions[s]
		if !ok {
			desc = fmt.Sprintf("Access %q", s)
		}
		out = append(out, ScopeDetail{Name: s, Description: desc})
	}
	return out
}
