-- 创建用户表
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

-- 创建客户端表
CREATE TABLE IF NOT EXISTS clients (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    client_id VARCHAR(255) NOT NULL UNIQUE,
    client_secret VARCHAR(255) NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    allowed_grant_types TEXT[] NOT NULL,
    allowed_scopes TEXT[] NOT NULL,
    user_id UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

-- 创建授权表
CREATE TABLE IF NOT EXISTS authorizations (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    client_id UUID NOT NULL REFERENCES clients(id),
    code VARCHAR(255) NOT NULL UNIQUE,
    redirect_uri TEXT NOT NULL,
    scope TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE(user_id, client_id, code)
);

-- 创建令牌表
CREATE TABLE IF NOT EXISTS tokens (
    id UUID PRIMARY KEY,
    access_token VARCHAR(255) NOT NULL UNIQUE,
    refresh_token VARCHAR(255) UNIQUE,
    token_type VARCHAR(50) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    scope TEXT,
    user_id UUID NOT NULL REFERENCES users(id),
    client_id UUID NOT NULL REFERENCES clients(id),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE
);

-- 创建索引
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_clients_client_id ON clients(client_id);
CREATE INDEX IF NOT EXISTS idx_authorizations_code ON authorizations(code);
CREATE INDEX IF NOT EXISTS idx_tokens_access_token ON tokens(access_token);
CREATE INDEX IF NOT EXISTS idx_tokens_refresh_token ON tokens(refresh_token);
CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_tokens_client_id ON tokens(client_id);

-- 插入测试客户端（如果不存在）
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM clients WHERE client_id = 'test_client') THEN
        INSERT INTO clients (
            id, 
            name, 
            client_id, 
            client_secret, 
            redirect_uris, 
            allowed_grant_types, 
            allowed_scopes, 
            created_at, 
            updated_at
        ) VALUES (
            'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11', 
            '测试客户端', 
            'test_client', 
            'test_secret', 
            ARRAY['http://localhost:3000/callback'], 
            ARRAY['authorization_code', 'refresh_token'], 
            ARRAY['profile', 'email'], 
            NOW(), 
            NOW()
        );
    END IF;
END
$$; 