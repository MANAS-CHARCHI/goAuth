CREATE TABLE user_otps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    user_id UUID REFERENCES users (id) ON DELETE CASCADE,
    otp VARCHAR(6) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_user_otps_user_id ON user_otps (user_id);

CREATE INDEX idx_user_otps_expires_at ON user_otps (expires_at);