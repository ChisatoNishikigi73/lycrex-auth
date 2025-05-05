use actix_web::{web, HttpResponse, Responder};
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;
use actix_multipart::Multipart;
use futures::{StreamExt, TryStreamExt};
use std::io::Write;
use base64::engine::Engine;

use crate::middleware::auth::AuthenticatedUser;
use crate::services::user as user_service;
use crate::models::LoginHistoryQuery;

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    username: Option<String>,
    email: Option<String>,
    avatar: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    old_password: String,
    new_password: String,
}

#[derive(Debug, Deserialize)]
pub struct ChangeUsernameRequest {
    username: String,
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

// 上传头像
pub async fn upload_avatar(
    path: web::Path<Uuid>,
    user: web::ReqData<AuthenticatedUser>,
    mut payload: Multipart,
    db: web::Data<PgPool>,
) -> impl Responder {
    // 检查是否是当前用户
    let user_id = path.into_inner();
    let auth_user = user.into_inner();
    
    if auth_user.user_id != user_id {
        return HttpResponse::Forbidden().json("无权修改其他用户的头像");
    }
    
    // 处理文件上传
    let mut avatar_data = None;
    
    while let Ok(Some(mut field)) = payload.try_next().await {
        let content_disposition = field.content_disposition();
        let field_name = content_disposition.get_name().unwrap_or_default();
        
        if field_name == "avatar" {
            // 读取文件内容到内存
            let mut buffer = Vec::new();
            
            while let Some(chunk) = field.next().await {
                let data = chunk.unwrap();
                buffer.write_all(&data).unwrap();
            }
            
            // 检查文件大小 (限制为4MB)
            if buffer.len() > 4 * 1024 * 1024 {
                return HttpResponse::BadRequest().json("头像文件太大，请上传小于4MB的文件");
            }
            
            // 将图像数据转换为base64
            let base64_data = base64::engine::general_purpose::STANDARD.encode(&buffer);
            avatar_data = Some(base64_data);
        }
    }
    
    // 如果成功获取了头像数据，更新用户
    if let Some(avatar) = avatar_data {
        match user_service::update_user(
            user_id,
            None,
            None,
            Some(avatar),
            &db,
        )
        .await
        {
            Ok(user) => HttpResponse::Ok().json(user),
            Err(err) => HttpResponse::BadRequest().json(err.to_string()),
        }
    } else {
        HttpResponse::BadRequest().json("未找到头像文件或处理失败")
    }
}

// 修改密码
pub async fn change_password(
    path: web::Path<Uuid>,
    user: web::ReqData<AuthenticatedUser>,
    data: web::Json<ChangePasswordRequest>,
    db: web::Data<PgPool>,
) -> impl Responder {
    // 检查是否是当前用户
    let user_id = path.into_inner();
    let auth_user = user.into_inner();
    if auth_user.user_id != user_id {
        return HttpResponse::Forbidden().json("无权修改其他用户的密码");
    }
    
    match user_service::update_user_password(
        user_id,
        &data.old_password,
        &data.new_password,
        &db,
    )
    .await
    {
        Ok(user) => HttpResponse::Ok().json(user),
        Err(err) => HttpResponse::BadRequest().json(err.to_string()),
    }
}

// 修改用户名
pub async fn change_username(
    path: web::Path<Uuid>,
    user: web::ReqData<AuthenticatedUser>,
    data: web::Json<ChangeUsernameRequest>,
    db: web::Data<PgPool>,
) -> impl Responder {
    // 检查是否是当前用户
    let user_id = path.into_inner();
    let auth_user = user.into_inner();
    if auth_user.user_id != user_id {
        return HttpResponse::Forbidden().json("无权修改其他用户的用户名");
    }
    
    match user_service::update_user(
        user_id,
        Some(data.username.clone()),
        None,
        None,
        &db,
    )
    .await
    {
        Ok(user) => HttpResponse::Ok().json(user),
        Err(err) => HttpResponse::BadRequest().json(err.to_string()),
    }
}