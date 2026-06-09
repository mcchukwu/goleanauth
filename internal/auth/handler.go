package auth

import (
	"encoding/json"
	"net/http"

	"goleanauth/internal/apperror"
	"goleanauth/internal/normalize"
	"goleanauth/internal/requestctx"
	"goleanauth/internal/response"
	"goleanauth/internal/validation"
	"goleanauth/pkg/config"
)

var cfg = config.Load()

type AuthHandler struct {
	AuthService *AuthService
}

func NewAuthHandler(authService *AuthService) *AuthHandler {
	return &AuthHandler{AuthService: authService}
}

// Register creates a new user account
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest

	// Decode request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.HandleError(w, apperror.ErrInvalidRequestBody)
		return
	}

	// Normalize
	if req.Phone != "" {
		normalized, err := normalize.Phone(req.Phone, "")
		if err != nil {
			response.ValidationError(w, map[string]string{"phone": "must be a valid phone number"})
			return
		}
		req.Phone = normalized
	}
	req.Email = normalize.Email(req.Email)

	// Validate request
	if err := validation.ValidateStruct(req); err != nil {
		response.ValidationError(w, err)
		return
	}

	// Call register service
	if err := h.AuthService.Register(r.Context(), req); err != nil {
		response.HandleError(w, err)
		return
	}

	// Return response
	response.Success(w, http.StatusCreated, "registration successful", nil)
}

// Login validates the user credentials and returns a JWT access token
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.HandleError(w, apperror.ErrInvalidRequestBody)
		return
	}

	// Normalize if identifier is a phone number
	req.Identifier = normalize.Identifier(req.Identifier, "")

	// Validate request
	if err := validation.ValidateStruct(req); err != nil {
		response.ValidationError(w, err)
		return
	}

	// Call login service
	accessToken, refreshToken, err := h.AuthService.Login(r.Context(), req)
	if err != nil {
		response.HandleError(w, err)
		return
	}

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		HttpOnly: true,
		Secure:   cfg.AppEnv == "production", // true in production HTTPS
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   60 * 60 * 24 * 30,
	})

	// Return response
	response.Success(w, http.StatusOK, "login successful", map[string]any{
		"access_token": accessToken,
	})
}

// GoogleCallback handles the Google OAuth callback
func (h *AuthHandler) GoogleCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		response.HandleError(w, apperror.ErrInvalidRequestBody)
		return
	}

	accessToken, refreshToken, err := h.AuthService.GoogleLogin(r.Context(), code)
	if err != nil {
		response.HandleError(w, err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		HttpOnly: true,
		Secure:   cfg.AppEnv == "production",
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   60 * 60 * 24 * 30,
	})

	response.Success(w, http.StatusOK, "login successful", map[string]any{
		"access_token": accessToken,
	})
}

// RefreshToken refreshes the session
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	// Read cookie
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		response.HandleError(w, apperror.ErrInvalidToken)
		return
	}

	accessToken, newRefreshToken, err := h.AuthService.RefreshToken(r.Context(), cookie.Value)
	if err != nil {
		response.HandleError(w, err)
		return
	}

	// Set new cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    newRefreshToken,
		HttpOnly: true,
		Secure:   cfg.AppEnv == "production", // true in production HTTPS
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   60 * 60 * 24 * 30,
	})

	// Return new access token
	response.Success(w, http.StatusOK, "token refreshed", map[string]any{
		"access_token": accessToken,
	})
}

// Logout invalidates the session
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// Get session id
	sessionID, ok := r.Context().Value(requestctx.SessionIDKey).(string)
	if !ok {
		response.HandleError(w, apperror.ErrExpiredToken)
		return
	}

	// Call logout service
	if err := h.AuthService.Logout(r.Context(), sessionID); err != nil {
		response.HandleError(w, err)
		return
	}

	// Delete refresh token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   cfg.AppEnv == "production", // true in production HTTPS
		MaxAge:   -1,
	})

	// Return response
	response.Success(w, http.StatusNoContent, "logout successful", nil)
}

// LogoutAllDevices revokes all sessions for a user
func (h *AuthHandler) LogoutAllDevices(w http.ResponseWriter, r *http.Request) {
	// Find user
	userID, ok := r.Context().Value(requestctx.UserIDKey).(string)
	if !ok {
		response.HandleError(w, apperror.ErrUserNotFound)
		return
	}

	// Call logoutalldevices service
	if err := h.AuthService.LogoutAllDevices(r.Context(), userID); err != nil {
		response.HandleError(w, err)
		return
	}

	// Revoke refresh token
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   cfg.AppEnv == "production",
		MaxAge:   -1,
	})

	// Return response
	response.Success(w, http.StatusNoContent, "logout successful", nil)
}
