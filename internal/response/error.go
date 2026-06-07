package response

import (
	"encoding/json"
	"errors"
	"net/http"

	"goleanauth/internal/apperror"
)

type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
type ErrorResponse struct {
	Success bool        `json:"success"`
	Error   ErrorDetail `json:"error"`
}

type ValidationErrorResponse struct {
	Success bool `json:"success"`
	Error   struct {
		Code    string            `json:"code"`
		Message string            `json:"message"`
		Fields  map[string]string `json:"fields"`
	} `json:"error"`
}

func Error(w http.ResponseWriter, status int, code string, message string) {
	w.Header().Set("Content-Type", "application/json")

	w.WriteHeader(status)

	json.NewEncoder(w).Encode(ErrorResponse{
		Success: false,
		Error: ErrorDetail{
			Code:    code,
			Message: message,
		},
	})
}

func ValidationError(w http.ResponseWriter, fields map[string]string) {
	w.Header().Set("Content-Type", "application/json")

	w.WriteHeader(http.StatusBadRequest)

	json.NewEncoder(w).Encode(ValidationErrorResponse{
		Success: false,
		Error: struct {
			Code    string            `json:"code"`
			Message string            `json:"message"`
			Fields  map[string]string `json:"fields"`
		}{
			Code:    "validation_error",
			Message: "validation failed",
			Fields:  fields,
		},
	})
}

func HandleError(w http.ResponseWriter, err error) {
	switch {
	// AUTH
	case errors.Is(err, apperror.ErrInvalidCredentials):
		Error(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or password")
	case errors.Is(err, apperror.ErrUnauthorized):
		Error(w, http.StatusUnauthorized, "unauthorized", "authentication required")
	case errors.Is(err, apperror.ErrForbidden):
		Error(w, http.StatusForbidden, "forbidden", "access denied")
	case errors.Is(err, apperror.ErrSessionExpired):
		Error(w, http.StatusUnauthorized, "session_expired", "session expired")
	case errors.Is(err, apperror.ErrInvalidToken):
		Error(w, http.StatusUnauthorized, "invalid_token", "invalid token")
	case errors.Is(err, apperror.ErrInvalidPassword):
		Error(w, http.StatusUnauthorized, "invalid_password", "invalid password")

		// USERS
	case errors.Is(err, apperror.ErrUserNotFound):
		Error(w, http.StatusConflict, "user_not_found", "user not found")
	case errors.Is(err, apperror.ErrEmailAlreadyExists):
		Error(w, http.StatusConflict, "email_already_exists", "email already exists")
	case errors.Is(err, apperror.ErrPhoneAlreadyExists):
		Error(w, http.StatusConflict, "phone_already_exists", "phone already exists")

	// VALIDATION
	case errors.Is(err, apperror.ErrValidation):
		Error(w, http.StatusBadRequest, "validation_error", "validation failed")

	// RATE LIMIT
	case errors.Is(err, apperror.ErrRateLimited):
		Error(w, http.StatusTooManyRequests, "rate_limited", "too many requests")

	// SYSTEM
	case errors.Is(err, apperror.ErrInternalServer):
		Error(w, http.StatusInternalServerError, "internal_server_error", "internal server error")
	case errors.Is(err, apperror.ErrDatabase):
		Error(w, http.StatusInternalServerError, "database_error", "database error")

	// DEFAULT
	default:
		Error(w, http.StatusInternalServerError, "internal_server_error", "internal server error")
	}
}

