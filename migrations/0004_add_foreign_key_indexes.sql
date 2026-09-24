CREATE INDEX IF NOT EXISTS idx_user_shlink_shlink ON user_shlink(shlink);

CREATE INDEX IF NOT EXISTS idx_user_shlink_user ON user_shlink(user);

CREATE INDEX IF NOT EXISTS idx_shlink_file_shlink ON shlink_file(shlink);

CREATE INDEX IF NOT EXISTS idx_shlink_endpoint_shlink ON shlink_endpoint(shlink);

CREATE INDEX IF NOT EXISTS idx_shlink_access_log_shlink ON shlink_access_log(shlink);

CREATE INDEX IF NOT EXISTS idx_shlink_file_content_hash ON shlink_file(content_hash);
