CREATE TABLE sessions(
    id SERIAL NOT NULL,
    user_id uuid NOT NULL,
    useragent text,
    ipaddress inet,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_active_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    isactive boolean NOT NULL DEFAULT true,
    PRIMARY KEY(id),
    CONSTRAINT sessions_userid_fkey FOREIGN key(user_id) REFERENCES users(id)
);
CREATE UNIQUE INDEX sessions_useragent_key ON public.sessions USING btree (useragent);
CREATE INDEX idx_sessions_userid ON public.sessions USING btree (user_id);