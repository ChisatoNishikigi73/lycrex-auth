#!/bin/bash

export RUN_ENV=production
export RUST_LOG=info,sqlx=off,sqlx::query=off

# 使用编译好的可执行文件而不是 cargo run
cd "$(dirname "$0")/.." # 切换到项目根目录
./lycrex-auth