-- Drop constraints first
ALTER TABLE IF EXISTS users
DROP CONSTRAINT IF EXISTS fk_users_updated_by;

ALTER TABLE IF EXISTS users
DROP CONSTRAINT IF EXISTS fk_users_deleted_by;

-- Drop dependent tables in correct order
DROP TABLE IF EXISTS sessions;

DROP TABLE IF EXISTS users;

DROP TABLE IF EXISTS roles;

-- Drop enum
DROP TYPE IF EXISTS genderEnum;

-- Drop indexes explicitly (if they are not automatically removed with tables)
DROP INDEX IF EXISTS idx_users_email;

DROP INDEX IF EXISTS idx_users_username;

DROP INDEX IF EXISTS idx_users_roleId;

DROP INDEX IF EXISTS idx_users_active;

DROP INDEX IF EXISTS idx_sessions_userId;

DROP INDEX IF EXISTS idx_sessions_active;