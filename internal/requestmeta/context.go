package requestmeta

import "context"

type Metadata struct {
	RequestID string
	TraceID   string
}

type contextKey struct{}

func With(ctx context.Context, metadata Metadata) context.Context {
	return context.WithValue(ctx, contextKey{}, metadata)
}

func From(ctx context.Context) Metadata {
	metadata, _ := ctx.Value(contextKey{}).(Metadata)
	return metadata
}
