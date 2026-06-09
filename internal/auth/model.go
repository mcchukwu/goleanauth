package auth

type OAuthUser struct {
	ProviderID string
	Provider   string // "google" | "apple"
	Email      string
	FirstName  string
	LastName   string
}
