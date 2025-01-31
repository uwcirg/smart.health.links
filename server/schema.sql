CREATE TABLE IF NOT EXISTS cas_item(
  hash VARCHAR(32) PRIMARY KEY UNIQUE,
  content BLOB UNIQUE,
  ref_count INTEGER DEFAULT(0)
);

CREATE TABLE IF NOT EXISTS user(
  id VARCHAR(43) PRIMARY KEY UNIQUE
);

CREATE TABLE IF NOT EXISTS user_shlink(
  user VARCHAR(43) REFERENCES user(id),
  shlink VARCHAR(43) REFERENCES shlink_access(id)
);

CREATE TABLE IF NOT EXISTS shlink_access(
  id VARCHAR(43) PRIMARY KEY UNIQUE,
  passcode_failures_remaining INTEGER DEFAULT(5),
  config_passcode TEXT,
  config_exp DATETIME,
  active BOOLEAN NOT NULL DEFAULT(true),
  management_token VARCHAR(43) NOT NULL
);

CREATE TABLE IF NOT EXISTS shlink_public(
  shlink VARCHAR(43) REFERENCES shlink_access(id),
  manifest_url TEXT NOT NULL,
  encryption_key VARCHAR(43),
  flag VARCHAR(3),
  label VARCHAR(80),
  version INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS shlink_file(
  shlink VARCHAR(43) REFERENCES shlink_access(id),
  label VARCHAR(80) DEFAULT NULL,
  added_time DATETIME NOT NULL DEFAULT(DATETIME('now')),
  content_type TEXT NOT NULL DEFAULT "application/json",
  content_hash TEXT REFERENCES cas_item(hash)
);

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

CREATE TABLE IF NOT EXISTS shlink_access_log(
  shlink VARCHAR(43) REFERENCES shlink_access(id),
  recipient TEXT NOT NULL,
  access_time DATETIME NOT NULL DEFAULT(DATETIME('now'))
);

CREATE TRIGGER IF NOT EXISTS delete_cas_on_ref_count_0
  AFTER UPDATE OF ref_count ON cas_item
  FOR EACH ROW WHEN new.ref_count=0
    BEGIN
        delete from cas_item where hash=new.hash;
    END;

CREATE TRIGGER IF NOT EXISTS insert_link_to_cas
  AFTER INSERT ON shlink_file
  FOR EACH ROW
    BEGIN
        update cas_item set ref_count=ref_count+1 where hash=NEW.content_hash;
    END;

CREATE TRIGGER IF NOT EXISTS disable_shlink_on_passcode_failure
  AFTER UPDATE ON shlink_access
  FOR EACH ROW
    BEGIN
        UPDATE shlink_access SET active=false WHERE id=new.id AND passcode_failures_remaining <= 0;
    END;
