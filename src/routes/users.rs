use actix_web::web;
use crate::handlers::users as user_handlers;
use crate::middleware::auth::Auth;
use uuid::Uuid;
use serde::Serialize;

// 新增结构体：客户端登录信息
#[derive(Debug, Serialize)]
pub struct ClientLoginInfo {
    pub client_id: Uuid,
    pub client_name: String,
    pub login_count: i64,
    pub last_login: String,
    pub client_type: Option<String>,
}

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/users")
            .wrap(Auth)
            .route("/me", web::get().to(user_handlers::get_current_user))
            .route("/{id}", web::get().to(user_handlers::get_user))
            .route("/{id}", web::put().to(user_handlers::update_user))
    );
} 