package requestctx

import "context"

func WithUserID(ctx context.Context, userID string) context.Context {
	return set(ctx, UserIDKey, userID)
}

func WithSessionID(ctx context.Context, sessionID string) context.Context {
	return set(ctx, SessionIDKey, sessionID)
}

func WithClientID(ctx context.Context, clientID string) context.Context {
	return set(ctx, ClientIDKey, clientID)
}

func WithScope(ctx context.Context, scope string) context.Context {
	return set(ctx, ScopeKey, scope)
}

func WithRequestID(ctx context.Context, requestID string) context.Context {
	return set(ctx, RequestIDKey, requestID)
}
