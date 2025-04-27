-- 创建客户端类型枚举
CREATE TYPE client_type AS ENUM ('openid', 'gitea', 'test');

-- 更新客户端表，添加client_type字段
ALTER TABLE clients ADD COLUMN IF NOT EXISTS client_type client_type NOT NULL DEFAULT 'openid'; 