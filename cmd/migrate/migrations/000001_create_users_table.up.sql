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


CREATE EXTENSION IF NOT EXISTS pgcrypto;
-- User Table
CREATE TABLE IF NOT EXISTS users(
    id UUID PRIMARY KEY DEFAULT  gen_random_uuid(),
    username VARCHAR(20) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(100) NOT NULL,
    lastPassword VARCHAR(100),
    passwordChangedAt TIMESTAMPTZ,
    lastPasswordResetAt TIMESTAMPTZ,
    roleId INT NOT NULL REFERENCES roles(id),
    signUpIP INET,
    lastLoginIP INET,
    userAgentAtCreation TEXT,
    failedLoginAttempts INT NOT NULL DEFAULT 0,
    failedLoginIp INET,
    failedLoginUserAgent TEXT,
    firstName VARCHAR(100),
    lastName VARCHAR(100),
    avatar VARCHAR(255),
    dob DATE,
    gender genderEnum,
    phoneNumberOne VARCHAR(13),
    phoneNumberTwo VARCHAR(13),
    address VARCHAR(255),
    userActivate BOOLEAN NOT NULL DEFAULT TRUE,
    userActivatedAt TIMESTAMPTZ,
    website VARCHAR(255),
    createdAt TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lastLogin TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lastModified TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    isDeleted BOOLEAN NOT NULL DEFAULT FALSE,
    deletedAt TIMESTAMPTZ
);


-- Recommended indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_roleId ON users(roleId);
CREATE INDEX IF NOT EXISTS idx_users_active ON users(id) WHERE isDeleted = FALSE;
