package domain

import "time"

type OutboxEvent struct {
	ID          string
	WorkspaceID string
	AggregateID string
	Type        string
	CreatedAt   time.Time
}
