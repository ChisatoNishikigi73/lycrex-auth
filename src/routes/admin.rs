use actix_web::web;
use crate::handlers::admin as admin_handlers;

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    // 管理员登录页面路由
    cfg.route("/admin/login", web::get().to(admin_handlers::admin_login_page));
    
    // 管理页面路由
    cfg.route("/admin", web::get().to(admin_handlers::admin_page));
    
    // 用户管理页面路由
    cfg.route("/admin/users", web::get().to(admin_handlers::admin_users_page));
    
    // 管理员登出路由
    cfg.route("/admin/logout", web::get().to(admin_handlers::admin_logout));
    
    // 管理API路由
    cfg.service(
        web::scope("/admin/api")
            .route("/login", web::post().to(admin_handlers::admin_login))
            .route("/providers", web::post().to(admin_handlers::create_provider))
            .route("/providers", web::get().to(admin_handlers::get_providers))
            .route("/providers/{id}", web::delete().to(admin_handlers::delete_provider))
            .route("/providers/{id}", web::put().to(admin_handlers::update_provider))
            // 用户管理API
            .route("/users", web::get().to(admin_handlers::get_users))
            .route("/users", web::post().to(admin_handlers::create_user))
            .route("/users/{id}", web::put().to(admin_handlers::update_user))
            .route("/users/{id}", web::delete().to(admin_handlers::delete_user))
            .route("/users/{id}/toggle-email-verification", web::post().to(admin_handlers::toggle_user_email_verification))
    );
} 