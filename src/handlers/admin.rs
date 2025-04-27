use actix_web::{web, HttpResponse, Responder};
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;
use actix_session::Session;

use crate::config::Config;
use crate::models::{ClientCreate, UserCreate, ClientType};
use crate::services::{client as client_service, user as user_service};

/// 创建提供方请求数据结构
#[derive(Debug, Deserialize)]
pub struct CreateProviderRequest {
    /// 提供方名称
    pub name: String,
    /// 客户端ID
    pub client_id: String,
    /// 客户端密钥
    pub client_secret: String,
    /// 重定向URI列表
    pub redirect_uris: Vec<String>,
    /// 客户端类型
    pub client_type: Option<ClientType>,
}

/// 更新提供方请求数据结构
#[derive(Debug, Deserialize)]
pub struct UpdateProviderRequest {
    /// 提供方名称
    pub name: Option<String>,
    /// 客户端ID
    pub client_id: Option<String>,
    /// 客户端密钥
    pub client_secret: Option<String>,
    /// 重定向URI列表
    pub redirect_uris: Option<Vec<String>>,
    /// 客户端类型
    pub client_type: Option<ClientType>,
}

/// 管理员登录请求数据结构
#[derive(Debug, Deserialize)]
pub struct AdminLoginRequest {
    /// 管理员密码
    pub password: String,
}

/// 创建用户请求数据结构
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    /// 用户名
    pub username: String,
    /// 邮箱
    pub email: String,
    /// 密码
    pub password: String,
}

/// 更新用户请求数据结构
#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    /// 用户名
    pub username: Option<String>,
    /// 邮箱
    pub email: Option<String>,
    /// 头像URL
    pub avatar_url: Option<String>,
}

/// 更新邮箱验证状态的请求数据结构
#[derive(Debug, Deserialize)]
pub struct ToggleEmailVerificationRequest {
    /// 邮箱验证状态
    pub email_verified: bool,
}

/// 用户列表查询参数
#[derive(Debug, Deserialize)]
pub struct UserListParams {
    /// 页码，从1开始
    pub page: Option<u32>,
    /// 每页记录数
    pub limit: Option<u32>,
    /// 搜索关键词（用户名或邮箱）
    pub search: Option<String>,
}

/// 管理员会话键
const ADMIN_SESSION_KEY: &str = "admin_authenticated";

/// 验证管理员密码是否正确
fn verify_admin_password(password: &str) -> bool {
    let config = Config::get_global();
    password == config.admin.password
}

/// 检查管理员是否已登录
fn is_admin_authenticated(session: &Session) -> bool {
    match session.get::<bool>(ADMIN_SESSION_KEY) {
        Ok(Some(true)) => true,
        _ => false,
    }
}

/// 显示管理员登录页面
pub async fn admin_login_page() -> impl Responder {
    log::info!("显示管理员登录页面");
    
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(crate::utils::templates::ADMIN_LOGIN_PAGE)
}

/// 处理管理员登录请求
pub async fn admin_login(
    data: web::Json<AdminLoginRequest>,
    session: Session,
) -> impl Responder {
    if verify_admin_password(&data.password) {
        // 设置会话标记
        if let Err(e) = session.insert(ADMIN_SESSION_KEY, true) {
            log::error!("设置管理员会话失败: {}", e);
            return HttpResponse::InternalServerError()
                .content_type("application/json")
                .json(serde_json::json!({
                    "error": "设置会话失败，请稍后重试"
                }));
        }
        
        log::info!("管理员登录成功");
        HttpResponse::Ok()
            .content_type("application/json")
            .json(serde_json::json!({
                "success": true,
                "message": "登录成功"
            }))
    } else {
        log::warn!("管理员登录失败：密码不正确");
        HttpResponse::Unauthorized()
            .content_type("application/json")
            .json(serde_json::json!({
                "success": false,
                "error": "密码不正确"
            }))
    }
}

/// 管理员登出
pub async fn admin_logout(session: Session) -> impl Responder {
    // 清除会话
    session.remove(ADMIN_SESSION_KEY);
    
    log::info!("管理员已登出");
    // 重定向到登录页面
    HttpResponse::Found()
        .append_header(("Location", "/admin/login"))
        .finish()
}

/// 显示管理员页面（需要登录）
pub async fn admin_page(session: Session) -> impl Responder {
    log::info!("访问管理员页面");
    
    // 检查管理员是否已登录
    if !is_admin_authenticated(&session) {
        log::warn!("未登录访问管理页面，重定向到登录页面");
        return HttpResponse::Found()
            .append_header(("Location", "/admin/login"))
            .finish();
    }
    
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(crate::utils::templates::ADMIN_PAGE)
}

/// 显示用户管理页面（需要登录）
pub async fn admin_users_page(session: Session) -> impl Responder {
    log::info!("访问用户管理页面");
    
    // 检查管理员是否已登录
    if !is_admin_authenticated(&session) {
        log::warn!("未登录访问用户管理页面，重定向到登录页面");
        return HttpResponse::Found()
            .append_header(("Location", "/admin/login"))
            .finish();
    }
    
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(crate::utils::templates::ADMIN_USERS_PAGE)
}

/// 创建提供方（客户端）
pub async fn create_provider(
    data: web::Json<CreateProviderRequest>,
    db: web::Data<PgPool>,
    session: Session,
) -> impl Responder {
    // 验证管理员是否已登录
    if !is_admin_authenticated(&session) {
        log::warn!("未登录尝试创建提供方");
        return HttpResponse::Unauthorized()
            .content_type("application/json")
            .json(serde_json::json!({ "error": "未登录或会话已过期，请重新登录" }));
    }
    
    // 创建客户端对象
    let client_create = ClientCreate {
        name: data.name.clone(),
        redirect_uris: data.redirect_uris.clone(),
        allowed_grant_types: vec!["authorization_code".to_string(), "refresh_token".to_string()],
        allowed_scopes: vec!["profile".to_string(), "email".to_string()],
        client_type: data.client_type.clone(),
    };
    
    // 使用自定义的client_id和client_secret创建客户端
    match client_service::create_provider_client(
        &client_create, 
        &data.client_id, 
        &data.client_secret,
        None, 
        &db
    ).await {
        Ok(client) => {
            log::info!("提供方创建成功：{}", client.name);
            HttpResponse::Created()
                .content_type("application/json")
                .json(client)
        },
        Err(err) => {
            log::warn!("创建提供方失败：{}", err);
            HttpResponse::BadRequest()
                .content_type("application/json")
                .json(serde_json::json!({ "error": err.to_string() }))
        },
    }
}

/// 获取所有提供方
pub async fn get_providers(
    db: web::Data<PgPool>,
    session: Session,
) -> impl Responder {
    // 验证管理员是否已登录
    if !is_admin_authenticated(&session) {
        log::warn!("未登录尝试获取提供方列表");
        return HttpResponse::Unauthorized()
            .content_type("application/json")
            .json(serde_json::json!({ "error": "未登录或会话已过期，请重新登录" }));
    }
    
    // 尝试获取所有客户端
    let result = client_service::get_all_clients(&db).await;
    
    match result {
        Ok(clients) => {
            log::info!("获取提供方列表，共{}个", clients.len());
            // 返回JSON数组
            HttpResponse::Ok()
                .content_type("application/json")
                .json(clients)
        },
        Err(err) => {
            // 记录错误
            log::error!("获取提供方列表失败：{}", err);
            // 返回错误JSON
            HttpResponse::InternalServerError()
                .content_type("application/json")
                .json(serde_json::json!({
                    "error": format!("获取提供方列表失败: {}", err)
                }))
        },
    }
}

/// 删除提供方
pub async fn delete_provider(
    path: web::Path<Uuid>,
    db: web::Data<PgPool>,
    session: Session,
) -> impl Responder {
    // 验证管理员是否已登录
    if !is_admin_authenticated(&session) {
        log::warn!("未登录尝试删除提供方");
        return HttpResponse::Unauthorized()
            .content_type("application/json")
            .json(serde_json::json!({ "error": "未登录或会话已过期，请重新登录" }));
    }
    
    let client_id = path.into_inner();
    match client_service::delete_client(client_id, &db).await {
        Ok(_) => {
            log::info!("提供方删除成功，ID: {}", client_id);
            HttpResponse::Ok()
                .content_type("application/json")
                .json(serde_json::json!({ "success": true }))
        },
        Err(err) => {
            log::warn!("删除提供方失败：{}", err);
            HttpResponse::BadRequest()
                .content_type("application/json")
                .json(serde_json::json!({ "error": err.to_string() }))
        },
    }
}

/// 更新提供方
pub async fn update_provider(
    path: web::Path<Uuid>,
    data: web::Json<UpdateProviderRequest>,
    db: web::Data<PgPool>,
    session: Session,
) -> impl Responder {
    // 验证管理员是否已登录
    if !is_admin_authenticated(&session) {
        log::warn!("未登录尝试更新提供方");
        return HttpResponse::Unauthorized()
            .content_type("application/json")
            .json(serde_json::json!({ "error": "未登录或会话已过期，请重新登录" }));
    }
    
    let client_id = path.into_inner();
    
    // 首先尝试更新基本信息
    let update_result = client_service::update_client(
        client_id,
        data.name.clone(),
        data.redirect_uris.clone(),
        None, // 不更新allowed_scopes
        data.client_type.clone(),
        &db
    ).await;
    
    // 如果基本信息更新成功且有需要更新客户端ID或密钥
    if let Ok(mut client) = update_result {
        // 检查是否需要更新客户端ID或密钥
        if data.client_id.is_some() || data.client_secret.is_some() {
            match client_service::update_client_credentials(
                client_id,
                data.client_id.clone(),
                data.client_secret.clone(),
                &db
            ).await {
                Ok(updated) => {
                    client = updated;
                    log::info!("提供方凭据更新成功，ID: {}", client_id);
                },
                Err(err) => {
                    log::warn!("更新提供方凭据失败：{}", err);
                    return HttpResponse::BadRequest()
                        .content_type("application/json")
                        .json(serde_json::json!({ "error": format!("更新凭据失败: {}", err.to_string()) }));
                }
            }
        }
        
        log::info!("提供方更新成功，ID: {}", client_id);
        HttpResponse::Ok()
            .content_type("application/json")
            .json(client)
    } else if let Err(err) = update_result {
        log::warn!("更新提供方失败：{}", err);
        HttpResponse::BadRequest()
            .content_type("application/json")
            .json(serde_json::json!({ "error": err.to_string() }))
    } else {
        // 这种情况理论上不会发生，但为了安全起见
        HttpResponse::InternalServerError()
            .content_type("application/json")
            .json(serde_json::json!({ "error": "更新提供方时发生未知错误" }))
    }
}

/// 获取用户列表
pub async fn get_users(
    query: web::Query<UserListParams>,
    db: web::Data<PgPool>,
    session: Session,
) -> impl Responder {
    // 验证管理员是否已登录
    if !is_admin_authenticated(&session) {
        log::warn!("未登录尝试获取用户列表");
        return HttpResponse::Unauthorized()
            .content_type("application/json")
            .json(serde_json::json!({ "error": "未登录或会话已过期，请重新登录" }));
    }
    
    // 处理分页参数
    let page = query.page.unwrap_or(1);
    let limit = query.limit.unwrap_or(10);
    let offset = (page - 1) * limit;
    
    // 执行查询
    let result = user_service::admin_get_user_list(
        offset as i64, 
        limit as i64, 
        query.search.as_deref(),
        &db
    ).await;
    
    match result {
        Ok((users, total)) => {
            log::info!("获取用户列表，共{}个", users.len());
            // 返回JSON响应
            HttpResponse::Ok()
                .content_type("application/json")
                .json(serde_json::json!({
                    "users": users,
                    "total": total,
                    "page": page,
                    "limit": limit
                }))
        },
        Err(err) => {
            log::error!("获取用户列表失败：{}", err);
            HttpResponse::InternalServerError()
                .content_type("application/json")
                .json(serde_json::json!({ "error": err.to_string() }))
        },
    }
}

/// 创建用户
pub async fn create_user(
    data: web::Json<CreateUserRequest>,
    db: web::Data<PgPool>,
    session: Session,
) -> impl Responder {
    // 验证管理员是否已登录
    if !is_admin_authenticated(&session) {
        log::warn!("未登录尝试创建用户");
        return HttpResponse::Unauthorized()
            .content_type("application/json")
            .json(serde_json::json!({ "error": "未登录或会话已过期，请重新登录" }));
    }
    
    // 创建用户对象
    let user_create = UserCreate {
        username: data.username.clone(),
        email: data.email.clone(),
        password: data.password.clone(),
    };
    
    // 创建用户
    match user_service::create_user(&user_create, &db).await {
        Ok(user) => {
            log::info!("用户创建成功，ID: {}", user.id);
            let user_response = crate::models::OpenIdUserResponse::from(user);
            HttpResponse::Created()
                .content_type("application/json")
                .json(user_response)
        },
        Err(err) => {
            log::error!("创建用户失败：{}", err);
            HttpResponse::BadRequest()
                .content_type("application/json")
                .json(serde_json::json!({ "error": err.to_string() }))
        },
    }
}

/// 更新用户
pub async fn update_user(
    path: web::Path<Uuid>,
    data: web::Json<UpdateUserRequest>,
    db: web::Data<PgPool>,
    session: Session,
) -> impl Responder {
    // 验证管理员是否已登录
    if !is_admin_authenticated(&session) {
        log::warn!("未登录尝试更新用户");
        return HttpResponse::Unauthorized()
            .content_type("application/json")
            .json(serde_json::json!({ "error": "未登录或会话已过期，请重新登录" }));
    }
    
    let user_id = path.into_inner();
    
    // 更新用户
    match user_service::update_user(
        user_id,
        data.username.clone(),
        data.email.clone(),
        data.avatar_url.clone(),
        &db,
    ).await {
        Ok(user) => {
            log::info!("用户更新成功，ID: {}", user_id);
            HttpResponse::Ok()
                .content_type("application/json")
                .json(user)
        },
        Err(err) => {
            log::error!("更新用户失败：{}", err);
            HttpResponse::BadRequest()
                .content_type("application/json")
                .json(serde_json::json!({ "error": err.to_string() }))
        },
    }
}

/// 删除用户
pub async fn delete_user(
    path: web::Path<Uuid>,
    db: web::Data<PgPool>,
    session: Session,
) -> impl Responder {
    // 验证管理员是否已登录
    if !is_admin_authenticated(&session) {
        log::warn!("未登录尝试删除用户");
        return HttpResponse::Unauthorized()
            .content_type("application/json")
            .json(serde_json::json!({ "error": "未登录或会话已过期，请重新登录" }));
    }
    
    let user_id = path.into_inner();
    
    // 删除用户
    match user_service::delete_user(user_id, &db).await {
        Ok(_) => {
            log::info!("用户删除成功，ID: {}", user_id);
            HttpResponse::Ok()
                .content_type("application/json")
                .json(serde_json::json!({ "success": true }))
        },
        Err(err) => {
            log::error!("删除用户失败：{}", err);
            HttpResponse::BadRequest()
                .content_type("application/json")
                .json(serde_json::json!({ "error": err.to_string() }))
        },
    }
}

/// 切换用户邮箱验证状态
pub async fn toggle_user_email_verification(
    path: web::Path<Uuid>,
    data: web::Json<ToggleEmailVerificationRequest>,
    db: web::Data<PgPool>,
    session: Session,
) -> impl Responder {
    // 验证管理员是否已登录
    if !is_admin_authenticated(&session) {
        log::warn!("未登录尝试切换用户邮箱验证状态");
        return HttpResponse::Unauthorized()
            .content_type("application/json")
            .json(serde_json::json!({ "error": "未登录或会话已过期，请重新登录" }));
    }
    
    let user_id = path.into_inner();
    
    // 更新邮箱验证状态
    match user_service::update_user_email_verified(user_id, data.email_verified, &db).await {
        Ok(user) => {
            log::info!(
                "用户邮箱验证状态已修改，ID: {}, 状态: {}", 
                user_id, 
                if data.email_verified { "已验证" } else { "未验证" }
            );
            HttpResponse::Ok()
                .content_type("application/json")
                .json(user)
        },
        Err(err) => {
            log::error!("修改用户邮箱验证状态失败：{}", err);
            HttpResponse::BadRequest()
                .content_type("application/json")
                .json(serde_json::json!({ "error": err.to_string() }))
        },
    }
} 