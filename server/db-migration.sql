/** Database migrations as of 2025-02-03, for user management updates */

/** Update shlink_access log table name */
ALTER TABLE shlink_access RENAME TO shlink_access_log;

/** Update shlink access admin table name */
ALTER TABLE shlink RENAME TO shlink_access;

/** Add user table */
CREATE TABLE IF NOT EXISTS user(
  id VARCHAR(43) PRIMARY KEY UNIQUE
);

/** Add user_shlink table */
CREATE TABLE IF NOT EXISTS user_shlink(
  user VARCHAR(43) REFERENCES user(id),
  shlink VARCHAR(43) REFERENCES shlink_access(id)
);

/** Add shlink_public table */
CREATE TABLE IF NOT EXISTS shlink_public(
  shlink VARCHAR(43) REFERENCES shlink_access(id),
  manifest_url TEXT NOT NULL,
  encryption_key VARCHAR(43) NOT NULL,
  flag VARCHAR(3),
  label VARCHAR(80),
  version INTEGER DEFAULT 1
);

/** Update shlink_file */
PRAGMA foreign_keys=off;
BEGIN TRANSACTION;
ALTER TABLE shlink_file RENAME TO _shlink_file_old;
CREATE TABLE IF NOT EXISTS shlink_file(
  shlink VARCHAR(43) REFERENCES shlink_access(id),
  label VARCHAR(80) DEFAULT NULL,
  added_time DATETIME NOT NULL DEFAULT(DATETIME('now')),
  content_type TEXT NOT NULL DEFAULT "application/json",
  content_hash TEXT REFERENCES cas_item(hash)
);
INSERT INTO shlink_file (shlink, content_type, content_hash)
  SELECT shlink, content_type, content_hash
  FROM _shlink_file_old;
COMMIT;
PRAGMA foreign_keys=on;

DROP TABLE _shlink_file_old;

/** Update shlink_endpoint */
PRAGMA foreign_keys=off;
BEGIN TRANSACTION;
ALTER TABLE shlink_endpoint RENAME TO _shlink_endpoint_old;
CREATE TABLE IF NOT EXISTS shlink_endpoint(
  id VARCHAR(43) PRIMARY KEY UNIQUE,
  shlink VARCHAR(43) REFERENCES shlink_access(id),
  added_time DATETIME NOT NULL DEFAULT(DATETIME('now')),
  endpoint_url TEXT NOT NULL,
  config_key VARCHAR(43) NOT NULL,
  config_client_id TEXT NOT NULL,
  config_client_secret TEXT,
  config_token_endpoint TEXT NOT NULL,
  config_refresh_token TEXT NOT NULL,
  refresh_time TEXT NOT NULL DEFAULT(DATETIME('now', '+5 minutes')),
  access_token_response TEXT NOT NULL
);
INSERT INTO shlink_endpoint (
  id,
  shlink,
  endpoint_url,
  config_key,
  config_client_id,
  config_client_secret,
  config_token_endpoint,
  config_refresh_token,
  refresh_time,
  access_token_response
)
SELECT
  id,
  shlink,
  endpoint_url,
  config_key,
  config_client_id,
  config_client_secret,
  config_token_endpoint,
  config_refresh_token,
  refresh_time,
  access_token_response
FROM _shlink_endpoint_old;
COMMIT;
PRAGMA foreign_keys=on;

DROP TABLE _shlink_endpoint_old;

/** Update disable_shlink_on_passcode_failure trigger */
DROP TRIGGER disable_shlink_on_passcode_failure;

CREATE TRIGGER IF NOT EXISTS disable_shlink_on_passcode_failure
AFTER UPDATE ON shlink_access
FOR EACH ROW
  BEGIN
      UPDATE shlink_access SET active=false WHERE id=new.id AND passcode_failures_remaining <= 0;
  END;