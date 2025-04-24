use actix_web::web;
use crate::handlers::users as user_handlers;
use crate::middleware::auth::Auth;

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/users")
            .wrap(Auth)
            .route("/me", web::get().to(user_handlers::get_current_user))
            .route("/{id}", web::get().to(user_handlers::get_user))
            .route("/{id}", web::put().to(user_handlers::update_user))
    );
} 