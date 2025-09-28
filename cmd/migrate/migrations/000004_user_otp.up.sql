CREATE TABLE IF NOT EXISTS user_otps (
    id SERIAL NOT NULL,
    user_id UUID REFERENCES users (id) ON DELETE CASCADE,
    email VARCHAR(100) NOT NULL UNIQUE,
    otp VARCHAR(6) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_user_otps_email ON user_otps (email);

CREATE INDEX idx_user_otps_expires_at ON user_otps (expires_at);