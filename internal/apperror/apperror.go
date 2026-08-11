package apperror

import "errors"

var (
	// AUTHENTICATION
	ErrInvalidCredentials         = errors.New("invalid credentials")
	ErrUnauthorized               = errors.New("unauthorized")
	ErrInvalidToken               = errors.New("invalid token")
	ErrExpiredToken               = errors.New("expired token")
	ErrSessionExpired             = errors.New("session expired")
	ErrSessionRevoked             = errors.New("session revoked")
	ErrMissingAuthorizationHeader = errors.New("missing authorization header")
	ErrInvalidAuthorizationHeader = errors.New("invalid authorization header")
	ErrInvalidPassword            = errors.New("invalid password")

	// AUTHORIZATION
	ErrForbidden               = errors.New("forbidden")
	ErrInsufficientPermissions = errors.New("insufficient permissions")

	// CLIENTS
	ErrInvalidClientCredentials = errors.New("invalid client credentials")
	ErrClientNotFound           = errors.New("client not found")
	ErrClientInactive           = errors.New("client inactive")
	ErrClientAlreadyExists      = errors.New("client already exists")

	// USERS
	ErrUserNotFound       = errors.New("user not found")
	ErrEmailAlreadyExists = errors.New("email already exists")
	ErrPhoneAlreadyExists = errors.New("phone already exists")
	ErrEmailNotVerified   = errors.New("email not verified")
	ErrPhoneNotVerified   = errors.New("phone not verified")
	ErrUserSuspended      = errors.New("user suspended")

	// VALIDATION
	ErrValidation              = errors.New("validation error")
	ErrInvalidRequestBody      = errors.New("invalid request body")
	ErrMissingRequiredField    = errors.New("missing required field")
	ErrInvalidEmail            = errors.New("invalid email")
	ErrInvalidStatusTransition = errors.New("invalid status transition")
	ErrWeakPassword            = errors.New("weak password")

	// RATE LIMITING
	ErrRateLimited = errors.New("too many requests")

	// OAUTH
	ErrUnsupportedGrantType    = errors.New("unsupported grant type")
	ErrInvalidRequest          = errors.New("invalid request")
	ErrInvalidScope            = errors.New("invalid scope")
	ErrUnsupportedResponseType = errors.New("unsupported response type")
	ErrInvalidRedirectURI      = errors.New("invalid redirect uri")

	// SYSTEM
	ErrInternalServer = errors.New("internal server error")
	ErrDatabase       = errors.New("database error")
)
