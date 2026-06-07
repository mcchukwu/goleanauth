package requestctx

import "context"

func WithUserID(ctx context.Context, userID string) context.Context {
	return set(ctx, UserIDKey, userID)
}

func WithSessionID(ctx context.Context, sessionID string) context.Context {
	return set(ctx, SessionIDKey, sessionID)
}

func WithRequestID(ctx context.Context, requestID string) context.Context {
	return set(ctx, RequestIDKey, requestID)
}
