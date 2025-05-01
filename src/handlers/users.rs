use actix_web::{web, HttpResponse, Responder};
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::middleware::auth::AuthenticatedUser;
use crate::services::user as user_service;

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    username: Option<String>,
    email: Option<String>,
    avatar: Option<String>,
}

// 获取当前用户信息
pub async fn get_current_user(
    user: web::ReqData<AuthenticatedUser>,
    db: web::Data<PgPool>,
) -> impl Responder {
    match user_service::get_user_by_id(user.into_inner().user_id, &db).await {
        Ok(user) => HttpResponse::Ok().json(user),
        Err(err) => HttpResponse::BadRequest().json(err.to_string()),
    }
}

// 获取用户信息
pub async fn get_user(
    path: web::Path<Uuid>,
    db: web::Data<PgPool>,
) -> impl Responder {
    match user_service::get_user_by_id(path.into_inner(), &db).await {
        Ok(user) => HttpResponse::Ok().json(user),
        Err(err) => HttpResponse::BadRequest().json(err.to_string()),
    }
}

// 更新用户
pub async fn update_user(
    path: web::Path<Uuid>,
    user: web::ReqData<AuthenticatedUser>,
    update: web::Json<UpdateUserRequest>,
    db: web::Data<PgPool>,
) -> impl Responder {
    // 检查是否是当前用户
    let user_id = path.into_inner();
    let auth_user = user.into_inner();
    if auth_user.user_id != user_id {
        return HttpResponse::Forbidden().json("无权修改其他用户的信息");
    }
    
    match user_service::update_user(
        user_id,
        update.username.clone(),
        update.email.clone(),
        update.avatar.clone(),
        &db,
    )
    .await
    {
        Ok(user) => HttpResponse::Ok().json(user),
        Err(err) => HttpResponse::BadRequest().json(err.to_string()),
    }
} 