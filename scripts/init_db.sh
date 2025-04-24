#!/bin/bash

pg_isready || { echo "PostgreSQL未运行，请先启动PostgreSQL服务"; exit 1; }

psql -c "CREATE DATABASE lycrex_auth;" 2>/dev/null || echo "开发环境数据库lycrex_auth已存在或创建失败"

psql -c "CREATE DATABASE lycrex_auth_test;" 2>/dev/null || echo "测试环境数据库lycrex_auth_test已存在或创建失败"

echo "数据库初始化完成"