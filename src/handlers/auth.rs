//! 认证处理模块
//! 
//! 本模块实现了OAuth2认证相关的请求处理函数，包括授权、令牌颁发、用户信息获取等功能。
//! 支持标准的OAuth2流程以及自定义的认证方式。

use actix_web::{web, HttpResponse, Responder};
use chrono::Utc;
use sqlx::{PgPool, query, Row};
use uuid::Uuid;
use serde_json::{self, json};

use crate::middleware::auth::AuthenticatedUser;
use crate::models::{AuthorizationRequest, TokenRequest, UserCreate, UserLogin, User, OAuthResponseHandler};
use crate::services::{auth as auth_service, user as user_service};

/// 构建登录页面重定向URL的辅助函数
/// 
/// # 参数
/// * `query` - 授权请求参数
fn build_login_redirect_url(query: &web::Query<AuthorizationRequest>) -> String {
    format!(
        "/login?client_id={}&redirect_uri={}&response_type={}&scope={}&state={}",
        query.client_id,
        query.redirect_uri,
        query.response_type,
        query.scope.as_deref().unwrap_or(""),
        query.state.as_deref().unwrap_or("")
    )
}

/// 构建OAuth重定向URL的辅助函数（带授权码）
/// 
/// # 参数
/// * `redirect_uri` - 重定向URI
/// * `code` - 授权码
/// * `state` - 可选的状态参数
fn build_oauth_redirect_url(redirect_uri: &str, code: &str, state: Option<&str>) -> String {
    let mut url = format!("{}?code={}", redirect_uri, code);
    
    // 添加state参数（如果存在）
    if let Some(state_value) = state {
        url.push_str(&format!("&state={}", state_value));
    }
    
    url
}

/// 创建HTML错误响应
/// 
/// # 参数
/// * `title` - 错误标题
/// * `message` - 错误消息
fn create_html_error(title: &str, message: &str) -> HttpResponse {
    HttpResponse::Forbidden()
        .content_type("text/html; charset=utf-8")
        .body(format!(
            "<html><body><h2>{}</h2><p>{}</p><p><a href='/login'>返回登录</a></p></body></html>",
            title, message
        ))
}

/// 验证用户邮箱状态
/// 
/// # 参数
/// * `user_id` - 用户ID
/// * `db` - 数据库连接池
/// * `session` - 用户会话
/// 
/// # 返回
/// * `Ok(())` - 验证通过
/// * `Err(HttpResponse)` - 验证失败，包含HTTP响应
async fn verify_user_email(
    user_id: Uuid, 
    db: &web::Data<PgPool>, 
    session: &actix_session::Session
) -> Result<(), HttpResponse> {
    match user_service::find_user_by_id(user_id, db).await {
        Ok(Some(user)) => {
            // 获取全局配置
            let config = crate::config::Config::get_global();
            
            // 根据配置决定是否检查邮箱验证状态
            if config.security.require_email_verification && !user.email_verified {
                log::warn!("用户 {} 邮箱未验证，拒绝授权", user_id);
                session.purge(); // 清除会话
                
                // 返回错误信息
                return Err(create_html_error(
                    "授权失败", 
                    "您的邮箱尚未验证。请联系管理员进行验证后再尝试登录。"
                ));
            }
            Ok(())
        },
        Ok(None) => {
            log::warn!("用户ID在数据库中不存在: {}", user_id);
            session.purge();
            Err(HttpResponse::NotFound().json("用户不存在"))
        },
        Err(e) => {
            log::error!("验证用户邮箱时数据库错误: {}", e);
            Err(HttpResponse::InternalServerError()
                .content_type("text/html; charset=utf-8")
                .body("<html><body><h2>服务器错误</h2><p>无法验证用户状态，请稍后再试。</p></body></html>"))
        }
    }
}

/// 检查用户令牌有效性
/// 
/// # 参数
/// * `user_id` - 用户ID
/// * `db` - 数据库连接池
/// 
/// # 返回
/// * `Ok(true)` - 用户有有效令牌
/// * `Ok(false)` - 用户没有有效令牌
/// * `Err(String)` - 查询出错
async fn check_user_token_validity(
    user_id: Uuid, 
    db: &web::Data<PgPool>
) -> Result<bool, String> {
    match sqlx::query(r#"SELECT COUNT(*) FROM tokens WHERE user_id = $1 AND revoked = false"#)
        .bind(user_id)
        .fetch_one(db.get_ref())
        .await 
    {
        Ok(row) => {
            let token_count: i64 = row.get(0);
            log::info!("用户 {} 有 {} 个有效令牌", user_id, token_count);
            Ok(token_count > 0)
        },
        Err(e) => {
            log::error!("检查用户令牌时数据库错误: {}", e);
            Err(e.to_string())
        }
    }
}

/// 获取请求中的用户ID（从URL参数）
/// 
/// # 参数
/// * `req` - HTTP请求
/// 
/// # 返回
/// * `Some(String)` - 找到的用户ID
/// * `None` - 未找到用户ID
fn get_user_id_from_params(req: &actix_web::HttpRequest) -> Option<String> {
    req.query_string()
        .split('&')
        .find_map(|param| {
            if param.starts_with("user_id=") {
                Some(param.split('=').nth(1).unwrap_or("").to_string())
            } else {
                None
            }
        })
}

/// 处理授权码创建和重定向
/// 
/// # 参数
/// * `user_id` - 用户ID
/// * `query` - 授权请求参数
/// * `db` - 数据库连接池
/// 
/// # 返回
/// * `HttpResponse` - HTTP响应
async fn handle_authorization_code(
    user_id: Uuid,
    query: &web::Query<AuthorizationRequest>,
    db: &web::Data<PgPool>
) -> HttpResponse {
    log::info!("为用户 {} 创建授权码", user_id);
    match auth_service::create_authorization(user_id, query, db).await {
        Ok(code) => {
            // 构建重定向URL
            let redirect_url = build_oauth_redirect_url(&query.redirect_uri, &code, query.state.as_deref());
            
            log::info!("授权成功，重定向到: {}", redirect_url);
            HttpResponse::TemporaryRedirect()
                .append_header(("Location", redirect_url))
                .finish()
        }
        Err(err) => {
            log::error!("创建授权码失败: {}", err);
            HttpResponse::BadRequest().json(err.to_string())
        },
    }
}

/// 授权端点 - 处理OAuth2授权请求
///
/// 支持标准OAuth2流程和Lycrex特定的授权类型。处理用户认证状态检查、
/// 邮箱验证状态检查和令牌有效性检查，并生成授权码。
#[allow(clippy::too_many_lines)]
pub async fn authorize(
    query: web::Query<AuthorizationRequest>,
    session: actix_session::Session,
    req: actix_web::HttpRequest,
    db: web::Data<PgPool>,
) -> impl Responder {
    // 检查必需参数
    if query.client_id.is_empty() || query.redirect_uri.is_empty() || query.response_type.is_empty() {
        log::warn!("授权请求缺少必需参数");
        return HttpResponse::Found()
            .append_header(("Location", "/"))
            .finish();
    }
    
    // 处理已知的OAuth响应类型请求
    if OAuthResponseHandler::is_known_response_type(&query.response_type) {
        log::info!("检测到OAuth响应类型请求: {}", query.response_type);
        
        // 尝试从URL参数或会话中获取用户ID
        let user_id = get_user_id_from_params(&req)
            .or_else(|| session.get::<String>("user_id").ok().flatten());
            
        // 如果没有用户ID，重定向到登录页面
        if user_id.is_none() {
            let redirect_url = build_login_redirect_url(&query);
            log::info!("未找到用户ID，重定向到登录页面: {}", redirect_url);
            return HttpResponse::TemporaryRedirect()
                .append_header(("Location", redirect_url))
                .finish();
        }
        
        // 解析用户ID并创建授权码
        match Uuid::parse_str(&user_id.unwrap()) {
            Ok(id) => {
                log::info!("成功解析用户ID: {}, 创建授权码", id);
                return handle_authorization_code(id, &query, &db).await;
            },
            Err(e) => {
                log::error!("无法解析用户ID: {}", e);
                return HttpResponse::BadRequest().json(format!("无效的用户ID: {}", e));
            }
        }
    }
    
    // 检查会话状态和用户ID
    return process_standard_authorization(query, session, req, db).await;
}

/// 处理标准授权流程
async fn process_standard_authorization(
    query: web::Query<AuthorizationRequest>,
    session: actix_session::Session,
    req: actix_web::HttpRequest,
    db: web::Data<PgPool>,
) -> HttpResponse {
    log::info!("处理标准授权请求");
    
    // 检查会话是否标记为已退出
    if let Ok(Some(true)) = session.get::<bool>("logged_out") {
        log::info!("会话已明确标记为退出状态，需要重新登录");
        session.purge();
        let redirect_url = build_login_redirect_url(&query);
        return HttpResponse::TemporaryRedirect()
            .append_header(("Location", redirect_url))
            .finish();
    }
    
    // 从URL参数尝试获取用户ID
    if let Some(user_id) = get_user_id_from_params(&req) {
        if !user_id.is_empty() {
            log::info!("从URL参数中获取到用户ID: {}", user_id);
            
            if let Ok(id) = Uuid::parse_str(&user_id) {
                // 检查用户邮箱是否已验证
                if let Err(resp) = verify_user_email(id, &db, &session).await {
                    return resp;
                }
                
                // 创建授权码并处理重定向
                return handle_authorization_code(id, &query, &db).await;
            } else {
                log::error!("无法解析URL参数中的用户ID");
            }
        }
    }
    
    // 检查会话中的用户ID
    let user_id_result = session.get::<String>("user_id");
    if user_id_result.is_err() || user_id_result.as_ref().ok().unwrap_or(&None).is_none() {
        log::info!("会话中没有有效的用户ID，清除会话并重定向到登录页面");
        session.purge();
        
        let redirect_url = build_login_redirect_url(&query);
        return HttpResponse::TemporaryRedirect()
            .append_header(("Location", redirect_url))
            .finish();
    }
    
    // 处理会话中的用户ID
    let user_id_str = user_id_result.unwrap().unwrap();
    log::info!("从会话中获取到用户ID: {}", user_id_str);
    
    match Uuid::parse_str(&user_id_str) {
        Ok(id) => {
            log::info!("成功解析用户ID为Uuid: {}", id);
            
            // 检查用户邮箱是否已验证
            if let Err(resp) = verify_user_email(id, &db, &session).await {
                return resp;
            }
            
            // 检查令牌有效性
            if let Ok(has_valid_tokens) = check_user_token_validity(id, &db).await {
                if !has_valid_tokens {
                    log::info!("用户 {} 没有有效令牌，强制重新登录", id);
                    session.purge();
                    let redirect_url = build_login_redirect_url(&query);
                    
                    return HttpResponse::TemporaryRedirect()
                        .append_header(("Location", redirect_url))
                        .finish();
                }
            }
            
            // 创建授权码
            handle_authorization_code(id, &query, &db).await
        },
        Err(e) => {
            log::error!("无法解析会话中的用户ID: {}", e);
            // 会话中的用户ID无效，清除会话并重定向到登录页面
            session.purge();
            let redirect_url = build_login_redirect_url(&query);
            
            HttpResponse::TemporaryRedirect()
                .append_header(("Location", redirect_url))
                .finish()
        }
    }
}

/// 令牌端点 - 处理OAuth2令牌请求
///
/// 支持从授权码交换访问令牌，处理JSON和表单格式的请求。
pub async fn token(
    token_req_json: Option<web::Json<TokenRequest>>,
    token_req_form: Option<web::Form<TokenRequest>>,
    req: actix_web::HttpRequest,
    db: web::Data<PgPool>,
) -> impl Responder {
    // 从JSON或表单数据中获取TokenRequest
    let token_req = if let Some(json) = token_req_json {
        json.into_inner()
    } else if let Some(form) = token_req_form {
        form.into_inner()
    } else {
        log::error!("令牌请求不包含有效的JSON或表单数据");
        return HttpResponse::BadRequest().json("无效的请求格式，需要JSON或表单数据");
    };
    
    log::info!("处理令牌请求，客户端ID: {}, 授权类型: {}", 
        token_req.client_id, token_req.grant_type);
    log::debug!("令牌请求方法: {}, URI: {}", req.method(), req.uri());
    
    match auth_service::exchange_token(&token_req, &db).await {
        Ok(token) => {
            log::info!("令牌交换成功，生成令牌ID: {}", token.id);
            let token_response = token.to_response(Utc::now());
            HttpResponse::Ok().json(token_response)
        }
        Err(err) => {
            log::error!("令牌交换失败: {}", err);
            HttpResponse::BadRequest().json(err.to_string())
        },
    }
}

/// 用户信息端点 - 提供已认证用户的信息
///
/// 根据访问令牌返回用户信息，支持多种令牌验证方式和客户端类型适配。
pub async fn userinfo(
    user: Option<web::ReqData<AuthenticatedUser>>,
    req: actix_web::HttpRequest,
    db: web::Data<PgPool>,
) -> impl Responder {
    // 获取请求的所有头部信息并记录
    let headers = req.headers();
    log::debug!("用户信息端点请求: {} {}", req.method(), req.uri());
    
    // 尝试从授权头中提取令牌
    let mut token_from_header = None;
    if let Some(auth_header) = headers.get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") {
                token_from_header = Some(auth_str[7..].to_string());
                log::debug!("从Authorization头中获取到访问令牌");
            }
        }
    }
    
    // 尝试三种方式获取用户信息
    if let Some(user_data) = user {
        // 1. 从中间件获取用户
        let user_id = user_data.into_inner().user_id;
        log::info!("通过认证中间件获取用户: {}", user_id);
        process_userinfo_request(user_id, token_from_header, db).await
    } else if let Some(token) = token_from_header {
        // 2. 手动验证Authorization头中的令牌
        verify_token_and_get_userinfo(&token, db).await
    } else {
        // 3. 尝试从URL参数中获取token
        let access_token = req.query_string()
            .split('&')
            .find_map(|param| {
                if param.starts_with("access_token=") {
                    Some(param.split('=').nth(1).unwrap_or(""))
                } else {
                    None
                }
            });
            
        if let Some(token) = access_token {
            verify_token_and_get_userinfo(token, db).await
        } else {
            // 如果没有认证用户，返回未认证错误
            log::error!("用户信息请求未提供有效认证");
            HttpResponse::Unauthorized().json("未提供有效的认证令牌")
        }
    }
}

/// 验证令牌并获取用户信息
async fn verify_token_and_get_userinfo(
    token: &str, 
    db: web::Data<PgPool>
) -> HttpResponse {
    match crate::utils::jwt::verify_token(token) {
        Ok(token_data) => {
            let user_id = token_data.claims.sub;
            log::info!("验证令牌成功，用户ID: {}", user_id);
            process_userinfo_request(user_id, Some(token.to_string()), db).await
        },
        Err(e) => {
            log::error!("验证令牌失败: {}", e);
            HttpResponse::Unauthorized().json(format!("无效的访问令牌: {}", e))
        }
    }
}

/// 处理用户信息请求的辅助函数
async fn process_userinfo_request(
    user_id: Uuid, 
    token: Option<String>,
    db: web::Data<PgPool>
) -> HttpResponse {
    // 如果有令牌，尝试获取客户端类型
    let client_type = if let Some(token_str) = token {
        match auth_service::get_client_type_by_token(&token_str, &db).await {
            Ok(ct) => {
                log::debug!("获取到客户端类型: {:?}", ct);
                ct
            },
            Err(e) => {
                log::warn!("获取客户端类型失败，使用默认类型: {}", e);
                crate::models::ClientType::default()
            }
        }
    } else {
        log::debug!("没有令牌，使用默认客户端类型");
        crate::models::ClientType::default()
    };
    
    // 根据客户端类型获取对应格式的用户信息
    match auth_service::get_user_info_for_client(user_id, client_type, &db).await {
        Ok(response) => {
            log::info!("成功获取用户 {} 信息，客户端类型: {:?}", user_id, client_type);
            HttpResponse::Ok().json(response)
        },
        Err(err) => {
            log::error!("获取用户 {} 信息失败: {}", user_id, err);
            HttpResponse::BadRequest().json(err.to_string())
        },
    }
}

/// 登录处理程序 - 验证用户凭证并建立会话
///
/// 验证用户的邮箱和密码，成功后创建会话并可选择性地重定向到授权页面。
pub async fn login(
    login: web::Json<UserLogin>,
    session: actix_session::Session,
    req: actix_web::HttpRequest,
    db: web::Data<PgPool>,
) -> impl Responder {
    // 验证用户凭证
    log::debug!("处理登录请求: {}", login.email);
    match auth_service::authenticate_user(&login.email, &login.password, &db).await {
        Ok(user) => {
            log::debug!("用户 {} 登录成功，用户ID: {}", login.email, user.id);
            
            // 清除会话，确保旧数据被完全清除
            session.purge();
            
            // 将用户ID保存到会话中
            if let Err(e) = session.insert("user_id", user.id.to_string()) {
                log::error!("无法将用户ID保存到会话: {}", e);
                return HttpResponse::InternalServerError().json(format!("会话错误: {}", e));
            }
            
            // 确保删除任何已登出标记
            session.remove("logged_out");
            
            // 明确指示需要将会话保存
            session.renew();
            
            log::debug!("用户ID已保存到会话中: {}", user.id);
            
            // 输出会话状态检查
            match session.get::<String>("user_id") {
                Ok(Some(id)) => {
                    log::debug!("会话立即检查：成功读取用户ID: {}", id);
                },
                Ok(None) => {
                    log::warn!("会话立即检查：无法读取用户ID，会话中不存在user_id");
                },
                Err(e) => {
                    log::error!("会话立即检查：读取user_id时出错: {}", e);
                }
            }
            
            // 检查是否需要重定向到授权页面（从查询参数中获取）
            let query_string = req.query_string();
            if !query_string.is_empty() {
                // 解析查询参数
                let mut params = Vec::new();
                for pair in query_string.split('&') {
                    if let Some((k, v)) = pair.split_once('=') {
                        params.push((k, v));
                    }
                }
                
                // 检查是否包含OAuth相关参数
                let client_id = params.iter().find(|&&(k, _)| k == "client_id").map(|&(_, v)| v);
                let redirect_uri = params.iter().find(|&&(k, _)| k == "redirect_uri").map(|&(_, v)| v);
                let response_type = params.iter().find(|&&(k, _)| k == "response_type").map(|&(_, v)| v);
                
                // 如果有必要的参数，重定向到授权页面
                if let (Some(client_id), Some(redirect_uri), Some(response_type)) = (client_id, redirect_uri, response_type) {
                    let scope = params.iter().find(|&&(k, _)| k == "scope").map(|&(_, v)| v).unwrap_or("");
                    let state = params.iter().find(|&&(k, _)| k == "state").map(|&(_, v)| v).unwrap_or("");
                    
                    let redirect_url = format!(
                        "/api/oauth/authorize?client_id={}&redirect_uri={}&response_type={}&scope={}&state={}",
                        client_id, redirect_uri, response_type, scope, state
                    );
                    
                    log::info!("登录成功，重定向到授权页面: {}", redirect_url);
                    return HttpResponse::Found()
                        .append_header(("Location", redirect_url))
                        .finish();
                }
            }
            
            // 如果不需要重定向，返回用户信息
            HttpResponse::Ok().json(user)
        }
        Err(err) => {
            log::error!("用户 {} 登录失败: {}", login.email, err);
            HttpResponse::Unauthorized().json(err.to_string())
        },
    }
}

/// 注册处理程序 - 创建新用户
///
/// 处理用户注册请求，创建新用户并返回标准格式的用户信息。
pub async fn register(
    user: web::Json<UserCreate>,
    db: web::Data<PgPool>,
) -> impl Responder {
    log::info!("处理用户注册请求: {}", user.email);
    
    match user_service::create_user(&user, &db).await {
        Ok(user) => {
            log::info!("用户注册成功，用户ID: {}", user.id);
            // 返回用户信息，使用OpenID Connect标准格式
            let user_response = crate::models::OpenIdUserResponse::from(user);
            HttpResponse::Created().json(user_response)
        },
        Err(err) => {
            log::error!("用户注册失败: {}", err);
            HttpResponse::BadRequest().json(err.to_string())
        },
    }
}

/// 退出登录处理程序 - 销毁用户会话和令牌
///
/// 吊销用户的访问令牌，清除会话信息，并返回适当的响应。
pub async fn logout(
    session: actix_session::Session,
    req: actix_web::HttpRequest,
    db: web::Data<PgPool>,
) -> impl Responder {
    log::info!("处理用户退出登录请求");
    
    // 标记是否是API请求
    let is_api_request = req.headers().get("Accept")
        .and_then(|h| h.to_str().ok())
        .map(|accept| accept.contains("application/json"))
        .unwrap_or(false) || 
        req.headers().get("Authorization").is_some();
    
    // 吊销令牌，并获取用户ID
    let user_id = revoke_user_tokens(&req, &session, &db).await;
    
    // 记录会话已退出 (在清除会话前先记录)
    if let Ok(Some(user_id_str)) = session.get::<String>("user_id") {
        log::info!("用户 {} 会话已标记为退出状态", user_id_str);
    }
    
    // 完全清除会话
    session.purge();
    
    // 设置明确的会话标记，表示已退出
    if let Err(e) = session.insert("logged_out", true) {
        log::error!("无法设置退出标记: {}", e);
    }
    
    // 构建响应
    let mut response = if is_api_request {
        // 对API请求返回JSON响应
        HttpResponse::Ok().json(json!({
            "success": true,
            "message": "已成功退出登录并吊销令牌"
        }))
    } else {
        // 对页面请求返回重定向
        HttpResponse::Found()
            .append_header(("Location", "/"))
            .finish()
    };
    
    // 添加清除客户端cookie的头信息
    add_cookie_clearing_headers(&mut response);
    
    response
}

/// 吊销用户的令牌
async fn revoke_user_tokens(
    req: &actix_web::HttpRequest,
    session: &actix_session::Session,
    db: &web::Data<PgPool>
) -> Option<Uuid> {
    let mut user_id = None;
    
    // 1. 尝试从Authorization头中获取令牌
    if let Some(auth_header) = req.headers().get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") {
                let token = auth_str.trim_start_matches("Bearer ").trim();
                log::info!("从Authorization头中获取令牌准备吊销");
                
                // 吊销特定令牌
                match query(r#"UPDATE tokens SET revoked = true WHERE access_token = $1 AND revoked = false"#)
                    .bind(token)
                    .execute(db.get_ref())
                    .await
                {
                    Ok(result) => {
                        let affected = result.rows_affected();
                        if affected > 0 {
                            log::info!("成功吊销令牌");
                            
                            // 尝试从令牌中获取用户ID
                            if let Ok(token_data) = crate::utils::jwt::verify_token(token) {
                                user_id = Some(token_data.claims.sub);
                            }
                        } 
                    },
                    Err(e) => {
                        log::error!("吊销令牌时数据库错误: {}", e);
                    }
                }
            }
        }
    }
    
    // 2. 从会话中获取用户ID
    if user_id.is_none() {
        if let Ok(Some(user_id_str)) = session.get::<String>("user_id") {
            if let Ok(id) = Uuid::parse_str(&user_id_str) {
                user_id = Some(id);
                log::info!("从会话中获取用户ID: {}", id);
            }
        }
    }
    
    // 3. 如果有用户ID，吊销该用户的所有令牌
    if let Some(id) = user_id {
        match query(r#"UPDATE tokens SET revoked = true WHERE user_id = $1 AND revoked = false"#)
            .bind(id)
            .execute(db.get_ref())
            .await
        {
            Ok(result) => {
                let affected = result.rows_affected();
                log::info!("成功吊销用户 {} 的 {} 个令牌", id, affected);
            },
            Err(e) => {
                log::error!("吊销用户令牌时数据库错误: {}", e);
            }
        }
    }
    
    user_id
}

/// 添加清除客户端cookie的HTTP头
fn add_cookie_clearing_headers(response: &mut HttpResponse) {
    let headers = response.headers_mut();
    
    // 添加缓存控制头
    headers.append(
        actix_web::http::header::CACHE_CONTROL,
        "no-store, must-revalidate, max-age=0".parse().unwrap()
    );
    headers.append(
        actix_web::http::header::PRAGMA,
        "no-cache".parse().unwrap()
    );
    headers.append(
        actix_web::http::header::EXPIRES,
        "0".parse().unwrap()
    );
    
    // 覆盖当前会话cookie，设置为立即过期
    headers.append(
        actix_web::http::header::SET_COOKIE,
        "id=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; HttpOnly; SameSite=Lax".parse().unwrap()
    );
}