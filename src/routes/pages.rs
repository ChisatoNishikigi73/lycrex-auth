use actix_web::web;
use crate::handlers::pages as page_handlers;

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/", web::get().to(page_handlers::index_page))
        .route("/login", web::get().to(page_handlers::login_page))
        .route("/register", web::get().to(page_handlers::register_page))
        .route("/welcome", web::get().to(page_handlers::welcome_page));
} 