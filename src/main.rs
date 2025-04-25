mod config;
mod db;
mod models;
mod handlers;
mod services;
mod middleware;
mod utils;
mod routes;
mod errors;

use actix_cors::Cors;
use actix_web::{App, HttpServer, middleware::Logger, web};
use actix_session::{SessionMiddleware, storage::CookieSessionStore};
use actix_web::cookie::Key;
use env_logger::Env;
use log::{info, LevelFilter};

use crate::config::Config;
use crate::routes::configure_routes;

/// 配置日志系统
fn configure_logger(config: &Config) {
    let log_level = match config.log.level.to_lowercase().as_str() {
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        _ => LevelFilter::Info,
    };
    
    let env = Env::default().default_filter_or(config.log.level.clone());
    
    match config.log.format.as_str() {
        "json" => {
            // JSON格式日志需要自定义
            env_logger::Builder::from_env(env)
                .format(|buf, record| {
                    use std::io::Write;
                    let timestamp = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f");
                    writeln!(
                        buf,
                        "{{\"timestamp\":\"{}\",\"level\":\"{}\",\"target\":\"{}\",\"message\":\"{}\"}}",
                        timestamp,
                        record.level(),
                        record.target(),
                        record.args()
                    )
                })
                .filter(None, log_level)
                .init();
        },
        "pretty" => {
            // 美化格式日志
            env_logger::Builder::from_env(env)
                .format_timestamp_millis()
                .format_module_path(true)
                .filter(None, log_level)
                .init();
        },
        _ => {
            // 默认格式
            env_logger::init_from_env(env);
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // 加载配置
    let config = Config::load().expect("配置初始化失败");
    
    // 初始化全局配置（确保在任何使用配置的操作之前）
    let _ = Config::get_global();
    
    // 配置日志
    configure_logger(&config);
    
    info!("应用配置加载完成");
    
    // 初始化数据库连接
    let db_pool = match db::init_pool(&config).await {
        Ok(pool) => pool,
        Err(e) => {
            log::error!("数据库连接初始化失败: {}", e);
            log::error!("请确保PostgreSQL服务器正在运行并且可以访问。");
            log::error!("数据库连接字符串: {}", config.database.url);
            std::process::exit(1);
        }
    };
    
    // 创建会话密钥
    let secret_key = {
        let mut key_data = config.server.secret_key.as_bytes().to_vec();
        // 确保密钥长度足够（至少64字节）
        while key_data.len() < 64 {
            key_data.extend_from_slice(key_data.clone().as_slice());
        }
        key_data.truncate(64);
        Key::from(&key_data)
    };
    
    info!("🚀 启动 OAuth 服务器, 监听地址: {}:{}", config.server.host, config.server.port);
    
    // 启动HTTP服务器
    HttpServer::new(move || {
        // 配置CORS
        let mut cors = Cors::default();
        
        // 从配置中获取允许的域名
        for origin in &config.cors.allowed_origins {
            cors = cors.allowed_origin(origin);
        }
        
        // 添加其他CORS配置
        cors = cors
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
            .allowed_headers(vec![
                actix_web::http::header::AUTHORIZATION,
                actix_web::http::header::CONTENT_TYPE,
                actix_web::http::header::ACCEPT
            ])
            .expose_headers(vec!["Authorization"])
            .supports_credentials()
            .max_age(3600);
        
        App::new()
            .wrap(Logger::default())
            .wrap(cors)
            .wrap(
                SessionMiddleware::builder(
                    CookieSessionStore::default(), 
                    secret_key.clone()
                )
                .cookie_secure(true)
                .cookie_http_only(true)
                .cookie_name("lycrex_session".to_string())
                .cookie_path("/".to_string())
                .cookie_same_site(actix_web::cookie::SameSite::Lax)
                .cookie_domain(None)
                .session_lifecycle(
                    actix_session::config::PersistentSession::default()
                        .session_ttl(actix_web::cookie::time::Duration::hours(24))
                )
                .build()
            )
            .app_data(web::Data::new(db_pool.clone()))
            // 移除旧的静态文件处理服务
            // 静态文件现在通过路由系统处理
            .configure(configure_routes)
    })
    .bind(format!("{}:{}", config.server.host, config.server.port))?
    .run()
    .await
}
