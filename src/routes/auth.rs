use actix_web::web;
use crate::handlers::auth as auth_handlers;

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/oauth")
            .route("/authorize", web::get().to(auth_handlers::authorize))
            .route("/token", web::post().to(auth_handlers::token))
            .route("/userinfo", web::get().to(auth_handlers::userinfo))
    );
    
    cfg.service(
        web::scope("/auth")
            .route("/login", web::post().to(auth_handlers::login))
            .route("/register", web::post().to(auth_handlers::register))
            .route("/logout", web::post().to(auth_handlers::logout))
    );
} 