use sqlx::{postgres::PgPoolOptions, Pool, Postgres, Connection, PgConnection, Row};
use anyhow::{Result, anyhow};
use log::{info, error};
use std::io::{self, Write};
use std::process;
use url::Url;

use crate::config::Config;

/// PostgreSQL数据库连接池类型
pub type DbPool = Pool<Postgres>;

/// 检查数据库是否存在
pub async fn check_database_exists(database_url: &str) -> Result<bool> {
    // 解析数据库URL
    let url = Url::parse(database_url)?;
    
    // 获取数据库名称
    let db_name = url.path().trim_start_matches('/');
    if db_name.is_empty() {
        return Err(anyhow!("无法从数据库URL获取数据库名称"));
    }
    
    // 创建连接到默认数据库的URL
    let mut base_url = url.clone();
    base_url.set_path("/postgres");
    
    // 连接到默认数据库
    let mut conn = match PgConnection::connect(base_url.as_str()).await {
        Ok(conn) => conn,
        Err(e) => {
            error!("无法连接到PostgreSQL: {}", e);
            error!("请确保PostgreSQL服务器正在运行并且可以访问。");
            print!("请检查PostgreSQL服务是否已启动，然后按回车键重试...");
            io::stdout().flush().unwrap();
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            
            // 重试连接
            match PgConnection::connect(base_url.as_str()).await {
                Ok(conn) => conn,
                Err(e) => {
                    error!("再次尝试连接PostgreSQL失败: {}", e);
                    error!("无法继续，请确保PostgreSQL服务已启动");
                    process::exit(1);
                }
            }
        }
    };
    
    // 查询数据库是否存在
    let row = sqlx::query("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)")
        .bind(db_name)
        .fetch_one(&mut conn)
        .await?;
    
    let exists: bool = row.get(0);
    Ok(exists)
}

/// 创建新数据库
pub async fn create_database(database_url: &str) -> Result<()> {
    // 解析数据库URL
    let url = Url::parse(database_url)?;
    
    // 获取数据库名称
    let db_name = url.path().trim_start_matches('/');
    if db_name.is_empty() {
        return Err(anyhow!("无法从数据库URL获取数据库名称"));
    }
    
    // 创建连接到默认数据库的URL
    let mut base_url = url.clone();
    base_url.set_path("/postgres");
    
    // 连接到默认数据库
    let mut conn = PgConnection::connect(base_url.as_str()).await?;
    
    // 创建数据库
    info!("正在创建数据库 '{}'...", db_name);
    let query = format!("CREATE DATABASE \"{}\"", db_name);
    sqlx::query(&query).execute(&mut conn).await?;
    info!("数据库 '{}' 创建成功", db_name);
    
    Ok(())
}

/// 初始化数据库表结构
pub async fn init_database_tables(pool: &DbPool) -> Result<()> {
    info!("正在初始化数据库表...");
    
    // 创建用户表
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY,
            username VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL
        );"
    ).execute(pool).await?;
    
    // 创建客户端表
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS clients (
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
        );"
    ).execute(pool).await?;
    
    // 创建授权表
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS authorizations (
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
        );"
    ).execute(pool).await?;
    
    // 创建令牌表
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS tokens (
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
        );"
    ).execute(pool).await?;
    
    // 创建索引
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_clients_client_id ON clients(client_id);")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_authorizations_code ON authorizations(code);")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_tokens_access_token ON tokens(access_token);")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_tokens_refresh_token ON tokens(refresh_token);")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id);")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_tokens_client_id ON tokens(client_id);")
        .execute(pool).await?;
    
    // 插入测试客户端
    sqlx::query(
        "DO $$ 
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
        END $$;"
    ).execute(pool).await?;
    
    info!("数据库表初始化成功");
    Ok(())
}

/// 初始化数据库连接池并确保数据库和表结构存在
pub async fn init_pool(config: &Config) -> Result<DbPool> {
    let database_url = &config.database.url;
    info!("检查数据库 '{}'", database_url);
    
    // 检查数据库是否存在
    match check_database_exists(database_url).await {
        Ok(exists) => {
            if !exists {
                error!("数据库 '{}' 不存在", database_url.split('/').last().unwrap_or("lycrex_auth"));
                print!("数据库不存在，是否创建？[y/n]: ");
                io::stdout().flush().unwrap();
                
                let mut answer = String::new();
                io::stdin().read_line(&mut answer)?;
                
                if answer.trim().to_lowercase() == "y" {
                    match create_database(database_url).await {
                        Ok(_) => info!("数据库创建成功"),
                        Err(e) => {
                            error!("创建数据库失败: {}", e);
                            error!("无法继续执行，程序将退出");
                            process::exit(1);
                        }
                    }
                } else {
                    error!("用户取消数据库创建，程序将退出");
                    process::exit(1);
                }
            } else {
                info!("数据库已存在");
            }
        },
        Err(e) => {
            error!("检查数据库存在性失败: {}", e);
            print!("无法检查数据库是否存在，是否尝试创建？[y/n]: ");
            io::stdout().flush().unwrap();
            
            let mut answer = String::new();
            io::stdin().read_line(&mut answer)?;
            
            if answer.trim().to_lowercase() == "y" {
                if let Err(e) = create_database(database_url).await {
                    error!("创建数据库失败: {}", e);
                    error!("无法继续执行，程序将退出");
                    process::exit(1);
                }
            } else {
                error!("用户取消数据库创建，程序将退出");
                process::exit(1);
            }
        }
    }
    
    // 连接到数据库
    info!("连接数据库: {}", database_url);
    let pool = match PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await {
            Ok(pool) => {
                info!("数据库连接成功");
                pool
            },
            Err(e) => {
                error!("连接数据库失败: {}", e);
                error!("请确保PostgreSQL服务已启动且连接信息正确");
                process::exit(1);
            }
        };
    
    // 初始化数据库表
    if let Err(e) = init_database_tables(&pool).await {
        error!("初始化数据库表失败: {}", e);
        error!("请确保数据库结构正确");
        process::exit(1);
    }
    
    Ok(pool)
} 