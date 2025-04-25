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
DB_USER=${DB_USER:-"kawaaanime"}
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

# 检查数据库是否存在
echo "正在检查数据库是否存在..."
psql "$DB_CONN" -c "SELECT 1" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "错误: 数据库不存在"
    exit 1
fi

# 检查数据库是否已初始化
echo "正在检查数据库是否已初始化..."
psql "$DB_CONN" -c "SELECT 1" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "错误: 数据库未初始化"
    exit 1
fi

# 运行/migrations目录下的所有迁移文件
echo "正在运行迁移文件..."
for migration in "$MIGRATIONS_DIR"/*.sql; do
    echo "正在运行迁移文件: $migration"
    psql "$DB_CONN" -f "$migration"
done


echo "=== 数据库迁移应用完成 ==="
exit 0 