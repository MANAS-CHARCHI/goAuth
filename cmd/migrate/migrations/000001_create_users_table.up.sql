CREATE TABLE IF NOT EXISTS roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL
);
-- Create gender enum
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'genderenum') THEN
        CREATE TYPE genderEnum AS ENUM ('male', 'female', 'other');
    END IF;
END$$;

-- Insert default roles
INSERT INTO roles (name)
VALUES ('member'), ('admin'), ('owner')
ON CONFLICT (name) DO NOTHING;

-- User Table
CREATE TABLE IF NOT EXISTS users(
    id SERIAL PRIMARY KEY,
    username VARCHAR(20) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(100) NOT NULL,
    lastPassword VARCHAR(100),
    passwordChangedAt TIMESTAMP,
    lastPasswordResetAt TIMESTAMP,
    failedLoginAttempts INT NOT NULL DEFAULT 0,
    roleId INT NOT NULL REFERENCES roles(id),
    activationToken VARCHAR(255),
    passwordResetToken VARCHAR(255),
    signUpIP INET,
    lastLoginIP INET,
    userAgent TEXT,
    failedLoginUserAgent TEXT,
    userUpdatedBy INT,
    firstName VARCHAR(100),
    lastName VARCHAR(100),
    avatar VARCHAR(255),
    dob DATE,
    gender genderEnum,
    phoneNumberOne VARCHAR(13),
    phoneNumberTwo VARCHAR(13),
    address VARCHAR(255),
    userActivate BOOLEAN NOT NULL DEFAULT TRUE,
    userActivatedAt TIMESTAMP,
    website VARCHAR(255),
    createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lastLogin TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lastModified TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    isDeleted BOOLEAN NOT NULL DEFAULT FALSE,
    deletedAt TIMESTAMP,
    deletedBy INT
);

-- Add self-referencing constraints separately
ALTER TABLE users
    ADD CONSTRAINT fk_users_updated_by FOREIGN KEY (userUpdatedBy) REFERENCES users(id),
    ADD CONSTRAINT fk_users_deleted_by FOREIGN KEY (deletedBy) REFERENCES users(id);

-- Recommended indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_roleId ON users(roleId);
CREATE INDEX IF NOT EXISTS idx_users_active ON users(id) WHERE isDeleted = FALSE;

CREATE TABLE IF NOT EXISTS sessions (
    id SERIAL PRIMARY KEY,
    userId INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sessionToken VARCHAR(255) NOT NULL UNIQUE,
    userAgent TEXT,
    ipAddress INET,
    createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lastActiveAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    isActive BOOLEAN NOT NULL DEFAULT TRUE,
    expiresAt TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sessions_userId ON sessions(userId);
CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions(userId) WHERE isActive = TRUE;