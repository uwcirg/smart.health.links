-- Stop using the IdP `sub` claim directly as user.id. Add a system-generated
-- proxy id as the primary key and move the sub claim to its own column, so an
-- external identifier is never the FK target for a user's SHLs.
CREATE TABLE IF NOT EXISTS _user_new(
  id VARCHAR(43) PRIMARY KEY UNIQUE,
  sub TEXT NOT NULL UNIQUE
);

INSERT INTO _user_new (id, sub)
  SELECT lower(hex(randomblob(16))), id
  FROM user;

CREATE TABLE IF NOT EXISTS _user_shlink_new(
  user VARCHAR(43) REFERENCES _user_new(id),
  shlink VARCHAR(43) REFERENCES shlink_access(id)
);

INSERT INTO _user_shlink_new (user, shlink)
  SELECT _user_new.id, user_shlink.shlink
  FROM user_shlink
  JOIN _user_new ON _user_new.sub = user_shlink.user;

DROP TABLE user_shlink;

DROP TABLE user;

ALTER TABLE _user_new RENAME TO user;

ALTER TABLE _user_shlink_new RENAME TO user_shlink;
