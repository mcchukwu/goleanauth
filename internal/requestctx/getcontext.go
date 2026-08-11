package requestctx

import "context"

func UserID(ctx context.Context) (string, bool) {
	val, ok := get(ctx, UserIDKey)
	if !ok {
		return "", false
	}

	s, ok := val.(string)
	return s, ok
}

func SessionID(ctx context.Context) (string, bool) {
	val, ok := get(ctx, SessionIDKey)
	if !ok {
		return "", false
	}

	s, ok := val.(string)
	return s, ok
}

func ClientID(ctx context.Context) (string, bool) {
	val, ok := get(ctx, ClientIDKey)
	if !ok {
		return "", false
	}

	s, ok := val.(string)
	return s, ok
}

func Scope(ctx context.Context) (string, bool) {
	val, ok := get(ctx, ScopeKey)
	if !ok {
		return "", false
	}

	s, ok := val.(string)
	return s, ok
}

func RequestID(ctx context.Context) (string, bool) {
	val, ok := get(ctx, RequestIDKey)
	if !ok {
		return "", false
	}

	s, ok := val.(string)
	return s, ok
}
