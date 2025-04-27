#!/bin/bash

# 设置默认值
DB_USER=${POSTGRES_USER:-root}
DB_PASSWORD=${POSTGRES_PASSWORD:-""}
DB_HOST=${POSTGRES_HOST:-localhost}
DB_PORT=${POSTGRES_PORT:-5432}
DB_NAME=${DB_NAME:-"lycrex_auth"}
TEST_DB_NAME=${TEST_DB_NAME:-"lycrex_auth_test"}
RUN_ENV=${RUN_ENV:-"development"}

echo "当前运行环境: $RUN_ENV"
echo "数据库主机: $DB_HOST:$DB_PORT"
echo "数据库用户: $DB_USER"

# 检查PostgreSQL是否运行
pg_isready -h $DB_HOST -p $DB_PORT -U $DB_USER || { echo "PostgreSQL未运行，请先启动PostgreSQL服务"; exit 1; }

# 根据环境决定是否创建测试数据库
if [ "$RUN_ENV" = "production" ]; then
  CREATE_TEST_DB=false
  echo "生产环境: 不创建测试数据库"
else
  CREATE_TEST_DB=true
  echo "开发环境: 将同时创建测试数据库"
fi

# 创建生产数据库
if [ -z "$DB_PASSWORD" ]; then
  psql -h $DB_HOST -p $DB_PORT -U $DB_USER -c "CREATE DATABASE $DB_NAME;" 2>/dev/null || echo "数据库$DB_NAME已存在或创建失败"
else
  PGPASSWORD="$DB_PASSWORD" psql -h $DB_HOST -p $DB_PORT -U $DB_USER -c "CREATE DATABASE $DB_NAME;" 2>/dev/null || echo "数据库$DB_NAME已存在或创建失败"
fi

# 创建测试数据库（如果不是生产环境）
if [ "$CREATE_TEST_DB" = true ]; then
  if [ -z "$DB_PASSWORD" ]; then
    psql -h $DB_HOST -p $DB_PORT -U $DB_USER -c "CREATE DATABASE $TEST_DB_NAME;" 2>/dev/null || echo "数据库$TEST_DB_NAME已存在或创建失败"
  else
    PGPASSWORD="$DB_PASSWORD" psql -h $DB_HOST -p $DB_PORT -U $DB_USER -c "CREATE DATABASE $TEST_DB_NAME;" 2>/dev/null || echo "数据库$TEST_DB_NAME已存在或创建失败"
  fi
fi

# 检查是否存在迁移目录和工具
if [ -d "./migrations" ]; then
  echo "检测到迁移文件，准备执行数据库迁移..."
  
  # 检查是否安装了sqlx-cli
  if command -v sqlx &> /dev/null; then
    echo "使用sqlx-cli执行迁移..."
    
    # 设置数据库URL
    if [ -z "$DB_PASSWORD" ]; then
      DB_URL="postgres://$DB_USER@$DB_HOST:$DB_PORT/$DB_NAME"
    else
      DB_URL="postgres://$DB_USER:$DB_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME"
    fi
    
    # 执行迁移
    echo "正在迁移数据库: $DB_NAME"
    DATABASE_URL="$DB_URL" sqlx migrate run || { echo "迁移失败"; exit 1; }
    
    # 如果不是生产环境，也迁移测试数据库
    if [ "$CREATE_TEST_DB" = true ]; then
      if [ -z "$DB_PASSWORD" ]; then
        TEST_DB_URL="postgres://$DB_USER@$DB_HOST:$DB_PORT/$TEST_DB_NAME"
      else
        TEST_DB_URL="postgres://$DB_USER:$DB_PASSWORD@$DB_HOST:$DB_PORT/$TEST_DB_NAME"
      fi
      
      echo "正在迁移测试数据库: $TEST_DB_NAME"
      DATABASE_URL="$TEST_DB_URL" sqlx migrate run || { echo "测试数据库迁移失败"; }
    fi
  else
    echo "未发现sqlx-cli工具，跳过自动迁移"
    echo "您可以使用以下命令安装sqlx-cli: cargo install sqlx-cli"
    echo "然后手动执行迁移: DATABASE_URL=<数据库URL> sqlx migrate run"
  fi
else
  echo "未找到迁移目录，跳过迁移步骤"
fi

echo "数据库初始化完成"