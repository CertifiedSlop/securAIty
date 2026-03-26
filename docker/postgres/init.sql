CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE SCHEMA IF NOT EXISTS security;

GRANT ALL PRIVILEGES ON SCHEMA security TO security_user;

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA security TO security_user;

GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA security TO security_user;

ALTER DEFAULT PRIVILEGES IN SCHEMA security
    GRANT ALL ON TABLES TO security_user;

ALTER DEFAULT PRIVILEGES IN SCHEMA security
    GRANT ALL ON SEQUENCES TO security_user;

CREATE TABLE IF NOT EXISTS security.audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type VARCHAR(50) NOT NULL,
    event_data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_service VARCHAR(100),
    correlation_id UUID
);

CREATE TABLE IF NOT EXISTS security.secrets_metadata (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    secret_name VARCHAR(255) NOT NULL UNIQUE,
    secret_path VARCHAR(500) NOT NULL,
    vault_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by VARCHAR(100),
    is_active BOOLEAN NOT NULL DEFAULT true
);

CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON security.audit_log(event_type);

CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON security.audit_log(created_at);

CREATE INDEX IF NOT EXISTS idx_audit_log_correlation_id ON security.audit_log(correlation_id);

CREATE INDEX IF NOT EXISTS idx_secrets_metadata_name ON security.secrets_metadata(secret_name);

CREATE INDEX IF NOT EXISTS idx_secrets_metadata_active ON security.secrets_metadata(is_active);
