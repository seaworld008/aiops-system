CREATE INDEX CONCURRENTLY outbox_event_routing_idx
    ON outbox_events (event_type, available_at, created_at, id)
    WHERE delivered_at IS NULL;
