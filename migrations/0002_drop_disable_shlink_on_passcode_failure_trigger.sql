-- Superseded by an in-process IP-based rate limit on repeated passcode
-- failures (routers/api.ts); drops the trigger from any DB created before
-- that change so an SHL is no longer auto-deactivated on passcode failures.
DROP TRIGGER IF EXISTS disable_shlink_on_passcode_failure;
