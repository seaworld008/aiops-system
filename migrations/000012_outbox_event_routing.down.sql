BEGIN;

SET LOCAL lock_timeout = '5s';

DROP INDEX IF EXISTS outbox_event_routing_idx;

COMMIT;
