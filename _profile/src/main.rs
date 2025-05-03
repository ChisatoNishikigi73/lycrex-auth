use actix_files::Files;
use actix_web::{middleware, web, App, HttpServer};
use dotenv::dotenv;
use log::info;
use std::sync::Mutex;

// 模块声明
mod models;
mod config;
mod handlers;
mod utils;

// 从模块中重新导出
use config::OAuthConfig;
use models::ProcessedCodes;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // 加载环境变量
    dotenv().ok();
    
    // 初始化日志
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));
    
    // 获取服务器地址和端口
    let host = config::get_env_or_default("HOST", "127.0.0.1");
    let port = config::get_env_or_default("PORT", "3000").parse::<u16>().unwrap_or(3000);
    
    // 初始化OAuth配置
    let oauth_config = OAuthConfig::new();
    info!("OAuth重定向URI: {}", oauth_config.redirect_uri);
    
    // 创建HTTP客户端
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap();

    // 创建已处理授权码集合
    let processed_codes = web::Data::new(Mutex::new(ProcessedCodes {
        codes: std::collections::HashSet::new()
    }));

    // 启动服务器
    info!("启动服务器，监听地址: {}:{}", host, port);
    HttpServer::new(move || {
        // 初始化模板系统
        let mut tera = tera::Tera::new("src/templates/**/*").unwrap();
        tera.autoescape_on(vec!["html"]);
        
        App::new()
            .wrap(middleware::Logger::default())
            .app_data(web::Data::new(tera))
            .app_data(web::Data::new(oauth_config.clone()))
            .app_data(web::Data::new(client.clone()))
            .app_data(processed_codes.clone())
            .service(handlers::index)
            .service(handlers::oauth_callback)
            .service(handlers::profile)
            .service(handlers::logout)
            .service(handlers::get_user_info_api)
            .service(handlers::get_login_stats_api)
            .service(handlers::get_recent_clients_api)
            .service(handlers::upload_avatar)
            .service(Files::new("/static", "src/static"))
    })
    .bind((host, port))?
    .run()
    .await
}
