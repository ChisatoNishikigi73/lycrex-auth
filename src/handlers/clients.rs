use actix_web::{web, HttpResponse, Responder};
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::middleware::auth::AuthenticatedUser;
use crate::models::ClientCreate;
use crate::services::client as client_service;

#[derive(Debug, Deserialize)]
pub struct UpdateClientRequest {
    name: Option<String>,
    redirect_uris: Option<Vec<String>>,
    allowed_scopes: Option<Vec<String>>,
}

// 创建客户端
pub async fn create_client(
    client: web::Json<ClientCreate>,
    user: web::ReqData<AuthenticatedUser>,
    db: web::Data<PgPool>,
) -> impl Responder {
    let auth_user = user.into_inner();
    match client_service::create_client(&client, Some(auth_user.user_id), &db).await {
        Ok(client) => HttpResponse::Created().json(client),
        Err(err) => HttpResponse::BadRequest().json(err.to_string()),
    }
}

// 获取用户的所有客户端
pub async fn get_clients(
    user: web::ReqData<AuthenticatedUser>,
    db: web::Data<PgPool>,
) -> impl Responder {
    let auth_user = user.into_inner();
    match client_service::get_clients_by_user(auth_user.user_id, &db).await {
        Ok(clients) => HttpResponse::Ok().json(clients),
        Err(err) => HttpResponse::BadRequest().json(err.to_string()),
    }
}

// 获取特定客户端
pub async fn get_client(
    path: web::Path<Uuid>,
    db: web::Data<PgPool>,
) -> impl Responder {
    match client_service::get_client_by_id(path.into_inner(), &db).await {
        Ok(client) => HttpResponse::Ok().json(client),
        Err(err) => HttpResponse::BadRequest().json(err.to_string()),
    }
}

// 更新客户端
pub async fn update_client(
    path: web::Path<Uuid>,
    update: web::Json<UpdateClientRequest>,
    db: web::Data<PgPool>,
) -> impl Responder {
    match client_service::update_client(
        path.into_inner(),
        update.name.clone(),
        update.redirect_uris.clone(),
        update.allowed_scopes.clone(),
        &db,
    )
    .await
    {
        Ok(client) => HttpResponse::Ok().json(client),
        Err(err) => HttpResponse::BadRequest().json(err.to_string()),
    }
}

// 删除客户端
pub async fn delete_client(
    path: web::Path<Uuid>,
    db: web::Data<PgPool>,
) -> impl Responder {
    match client_service::delete_client(path.into_inner(), &db).await {
        Ok(_) => HttpResponse::NoContent().finish(),
        Err(err) => HttpResponse::BadRequest().json(err.to_string()),
    }
} 