mod auth;
mod clients;
mod users;
mod pages;

use actix_web::web;

/// 配置所有路由
/// 
/// 将所有子模块的路由配置统一注册到Actix Web应用
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    // API 路由
    cfg.service(
        web::scope("/api")
            .configure(auth::configure_routes)
            .configure(clients::configure_routes)
            .configure(users::configure_routes)
    );
    
    // 页面路由
    cfg.configure(pages::configure_routes);
} 