package requestctx

import "context"

type contextKey string

const (
	UserIDKey    contextKey = "user_id"
	SessionIDKey contextKey = "session_id"
	ClientIDKey  contextKey = "client_id"
	ScopeKey     contextKey = "scope"
	RequestIDKey contextKey = "request_id"
)

func set(ctx context.Context, key contextKey, value any) context.Context {
	return context.WithValue(ctx, key, value)
}

func get(ctx context.Context, key contextKey) (any, bool) {
	val := ctx.Value(key)
	if val == nil {
		return nil, false
	}

	return val, true
}
