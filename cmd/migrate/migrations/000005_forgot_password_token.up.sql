CREATE TABLE IF NOT EXISTS forgot_password_tokens (
    id SERIAL NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    otp VARCHAR(100) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_forgot_password_tokens_email ON forgot_password_tokens (email);

