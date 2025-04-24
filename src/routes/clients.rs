use actix_web::web;
use crate::handlers::clients as client_handlers;
use crate::middleware::auth::Auth;

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/clients")
            .wrap(Auth)
            .route("", web::post().to(client_handlers::create_client))
            .route("", web::get().to(client_handlers::get_clients))
            .route("/{id}", web::get().to(client_handlers::get_client))
            .route("/{id}", web::put().to(client_handlers::update_client))
            .route("/{id}", web::delete().to(client_handlers::delete_client))
    );
} 