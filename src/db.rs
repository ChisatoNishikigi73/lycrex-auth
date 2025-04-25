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

/// 简化的数据库表结构验证
pub async fn validate_database_structure(pool: &DbPool) -> Result<()> {
    info!("验证数据库结构...");
    
    // 检查users表是否存在
    let users_table_exists = sqlx::query("SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name = 'users'
    )")
    .fetch_one(pool)
    .await?
    .get::<bool, _>(0);
    
    if !users_table_exists {
        return Err(anyhow!("用户表不存在，请确保数据库结构正确"));
    }
    
    // 检查clients表是否存在
    let clients_table_exists = sqlx::query("SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name = 'clients'
    )")
    .fetch_one(pool)
    .await?
    .get::<bool, _>(0);
    
    if !clients_table_exists {
        return Err(anyhow!("客户端表不存在，请确保数据库结构正确"));
    }
    
    info!("数据库结构验证完成");
    Ok(())
}

/// 初始化数据库连接池并验证数据库结构
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
                        Ok(_) => {
                            error!("数据库已创建，但需要手动初始化数据库结构");
                            process::exit(1);
                        },
                        Err(e) => {
                            error!("创建数据库失败: {}", e);
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
            error!("检查数据库失败: {}", e);
            process::exit(1);
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
    
    // 验证数据库结构
    if let Err(e) = validate_database_structure(&pool).await {
        error!("数据库结构验证失败: {}", e);
        error!("请确保数据库结构已正确初始化");
        process::exit(1);
    }
    
    Ok(pool)
} 