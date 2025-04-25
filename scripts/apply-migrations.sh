#!/bin/bash

# 应用数据库迁移脚本

# 获取脚本所在目录的绝对路径
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
MIGRATIONS_DIR="$PROJECT_ROOT/migrations"

# 数据库连接信息
DB_HOST=${DB_HOST:-"localhost"}
DB_PORT=${DB_PORT:-"5432"}
DB_NAME=${DB_NAME:-"lycrex_auth"}
DB_USER=${DB_USER:-"postgres"}
DB_PASSWORD=${DB_PASSWORD:-""}

# 构建数据库连接字符串
if [ -n "$DB_PASSWORD" ]; then
    DB_CONN="postgres://$DB_USER:$DB_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME"
else
    DB_CONN="postgres://$DB_USER@$DB_HOST:$DB_PORT/$DB_NAME"
fi

echo "=== 开始应用数据库迁移 ==="
echo "数据库: $DB_NAME"
echo "迁移目录: $MIGRATIONS_DIR"

# 检查迁移文件是否存在
if [ ! -d "$MIGRATIONS_DIR" ]; then
    echo "错误: 迁移目录不存在: $MIGRATIONS_DIR"
    exit 1
fi

# 检查数据库连接
echo "正在检查数据库连接..."
psql "$DB_CONN" -c "SELECT 1" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "错误: 无法连接到数据库"
    exit 1
fi
echo "数据库连接成功"

# 检查用户表是否存在
echo "正在检查users表是否存在..."
USER_TABLE_EXISTS=$(psql "$DB_CONN" -t -c "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'users')")
USER_TABLE_EXISTS=$(echo $USER_TABLE_EXISTS | xargs)

if [ "$USER_TABLE_EXISTS" != "t" ]; then
    echo "users表不存在，需要创建初始表结构"
    
    # 应用初始表结构迁移
    echo "正在应用初始表结构迁移..."
    psql "$DB_CONN" -f "$MIGRATIONS_DIR/20230501000000_create_initial_tables.sql"
    if [ $? -ne 0 ]; then
        echo "错误: 创建初始表结构失败"
        exit 1
    fi
    echo "初始表结构创建成功"
fi

# 检查并添加email_verified和avatar_url字段
echo "正在检查email_verified和avatar_url字段..."
EMAIL_VERIFIED_EXISTS=$(psql "$DB_CONN" -t -c "SELECT EXISTS (SELECT FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'users' AND column_name = 'email_verified')")
EMAIL_VERIFIED_EXISTS=$(echo $EMAIL_VERIFIED_EXISTS | xargs)

AVATAR_URL_EXISTS=$(psql "$DB_CONN" -t -c "SELECT EXISTS (SELECT FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'users' AND column_name = 'avatar_url')")
AVATAR_URL_EXISTS=$(echo $AVATAR_URL_EXISTS | xargs)

if [ "$EMAIL_VERIFIED_EXISTS" != "t" ] || [ "$AVATAR_URL_EXISTS" != "t" ]; then
    echo "缺少必要字段，应用字段修复迁移..."
    psql "$DB_CONN" -f "$MIGRATIONS_DIR/20240426000000_fix_missing_fields.sql"
    if [ $? -ne 0 ]; then
        echo "错误: 添加字段失败"
        exit 1
    fi
    echo "字段添加成功"
fi

# 检查test_client是否存在，如果不存在则创建
echo "正在检查测试客户端是否存在..."
TEST_CLIENT_EXISTS=$(psql "$DB_CONN" -t -c "SELECT EXISTS (SELECT 1 FROM clients WHERE client_id = 'test_client')")
TEST_CLIENT_EXISTS=$(echo $TEST_CLIENT_EXISTS | xargs)

if [ "$TEST_CLIENT_EXISTS" != "t" ]; then
    echo "测试客户端不存在，创建测试客户端..."
    psql "$DB_CONN" -c "INSERT INTO clients (
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
    )"
    if [ $? -ne 0 ]; then
        echo "错误: 创建测试客户端失败"
        exit 1
    fi
    echo "测试客户端创建成功"
fi

echo "=== 数据库迁移应用完成 ==="
exit 0 