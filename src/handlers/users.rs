use actix_web::{web, HttpResponse, Responder};
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::middleware::auth::AuthenticatedUser;
use crate::services::user as user_service;
use crate::models::LoginHistoryQuery;

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
    match user_service::get_self_user_by_id(user.into_inner().user_id, &db).await {
        Ok(user) => HttpResponse::Ok().json(user),
        Err(err) => HttpResponse::BadRequest().json(err.to_string()),
    }
}

// 获取用户信息
pub async fn get_user(
    path: web::Path<Uuid>,
    db: web::Data<PgPool>,
) -> impl Responder {
    match user_service::get_self_user_by_id(path.into_inner(), &db).await {
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

// 获取用户登录历史
pub async fn get_login_history(
    path: web::Path<Uuid>,
    query: web::Query<LoginHistoryQuery>,
    user: web::ReqData<AuthenticatedUser>,
    db: web::Data<PgPool>,
) -> impl Responder {
    // 获取路径参数和查询参数
    let user_id = path.into_inner();
    let auth_user = user.into_inner();
    
    // 检查权限 - 只允许查询自己的登录历史
    if auth_user.user_id != user_id {
        return HttpResponse::Forbidden().json("无权查看其他用户的登录历史");
    }
    
    // 获取查询参数
    let start_date = query.start_date;
    let end_date = query.end_date;
    let days = query.days.unwrap_or(30).min(365);  // 默认30天，最多365天
    
    match user_service::get_login_history(user_id, start_date, end_date, days, &db).await {
        Ok(history) => HttpResponse::Ok().json(history),
        Err(err) => HttpResponse::BadRequest().json(err.to_string()),
    }
}

// 获取用户登录统计信息（不包含详细登录记录）
pub async fn get_login_stats(
    path: web::Path<Uuid>,
    query: web::Query<LoginHistoryQuery>,
    user: web::ReqData<AuthenticatedUser>,
    db: web::Data<PgPool>,
) -> impl Responder {
    // 获取路径参数和查询参数
    let user_id = path.into_inner();
    let auth_user = user.into_inner();
    
    // 检查权限 - 只允许查询自己的登录统计
    if auth_user.user_id != user_id {
        return HttpResponse::Forbidden().json("无权查看其他用户的登录统计");
    }
    
    // 获取查询参数
    let start_date = query.start_date;
    let end_date = query.end_date;
    let days = query.days.unwrap_or(30).min(365);  // 默认30天，最多365天
    
    match user_service::get_login_stats(user_id, start_date, end_date, days, &db).await {
        Ok(stats) => HttpResponse::Ok().json(stats),
        Err(err) => HttpResponse::BadRequest().json(err.to_string()),
    }
}