-- Records shlink lifecycle events for clients to display as history.
-- Update events are limited to passcode/expiration/label changes (the
-- only update types clients need to surface); other config changes aren't logged here.
CREATE TABLE IF NOT EXISTS shlink_event(
  shlink VARCHAR(43) REFERENCES shlink_access(id),
  event_type TEXT NOT NULL CHECK(event_type IN (
    'created',
    'updated_passcode',
    'updated_expiration',
    'updated_label',
    'expired',
    'deactivated',
    'reactivated',
    'file_added',
    'file_deleted',
    'file_updated',
    'endpoint_added',
    'endpoint_deleted',
    'endpoint_updated'
  )),
  event_time DATETIME NOT NULL DEFAULT(DATETIME('now')),
  detail TEXT
);

CREATE INDEX IF NOT EXISTS idx_shlink_event_shlink ON shlink_event(shlink);
