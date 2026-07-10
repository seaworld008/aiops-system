package domain

import (
	"encoding/json"
	"time"
)

type OutboxEvent struct {
	ID               string
	TenantID         string
	WorkspaceID      string
	AggregateType    string
	AggregateID      string
	AggregateVersion int64
	Type             string
	Payload          json.RawMessage
	CreatedAt        time.Time
	AvailableAt      time.Time
	ClaimedAt        time.Time
	ClaimedBy        string
	ClaimToken       string
	ClaimExpiresAt   time.Time
	DeliveredAt      time.Time
	Attempts         int
	LastErrorCode    string
}
