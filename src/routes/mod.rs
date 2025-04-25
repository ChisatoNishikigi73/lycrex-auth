mod auth;
mod clients;
mod users;
mod pages;
mod admin;

use actix_web::web;
use crate::utils::static_files::serve_static_file;

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
    
    // 管理员路由
    cfg.configure(admin::configure_routes);
    
    // 页面路由
    cfg.configure(pages::configure_routes);
    
    // 静态文件路由
    cfg.service(
        web::resource("/static/{path:.*}")
            .route(web::get().to(|path: web::Path<String>| {
                let file_path = path.into_inner();
                serve_static_file(file_path)
            }))
    );
} 