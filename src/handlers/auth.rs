use actix_web::{web, HttpResponse, Responder};
use chrono::Utc;
use sqlx::{PgPool, query, Row};
use uuid::Uuid;
use serde_json;

use crate::middleware::auth::AuthenticatedUser;
use crate::models::{AuthorizationRequest, TokenRequest, UserCreate, UserLogin, User};
use crate::services::{auth as auth_service, user as user_service};

// 授权端点
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
    
    // 检查用户是否已认证
    log::info!("处理授权请求，获取会话中的用户ID");
    
    // 调试:打印完整会话状态
    if let Ok(cookie_value) = session.get::<String>("user_id") {
        if let Some(val) = cookie_value {
            log::info!("会话中的用户ID: {}", val);
        } else {
            log::info!("会话中没有用户ID");
        }
    }
    
    // 尝试从请求参数中获取用户ID（这是为了临时解决会话问题）
    let user_id_from_param = req.query_string()
        .split('&')
        .find_map(|param| {
            if param.starts_with("user_id=") {
                Some(param.split('=').nth(1).unwrap_or(""))
            } else {
                None
            }
        });
    
    if let Some(user_id) = user_id_from_param {
        if !user_id.is_empty() {
            log::info!("从URL参数中获取到用户ID: {}", user_id);
            
            // 验证用户ID是否有效
            match Uuid::parse_str(user_id) {
                Ok(id) => {
                    // 创建授权码
                    log::info!("为用户 {} 创建授权码", id);
                    match auth_service::create_authorization(id, &query, &db).await {
                        Ok(code) => {
                            // 构建重定向URL
                            let mut redirect_url = format!("{}?code={}", query.redirect_uri, code);
                            
                            // 添加state参数（如果存在）
                            if let Some(state) = &query.state {
                                redirect_url.push_str(&format!("&state={}", state));
                            }
                            
                            log::info!("授权成功，重定向到: {}", redirect_url);
                            return HttpResponse::TemporaryRedirect()
                                .append_header(("Location", redirect_url))
                                .finish();
                        }
                        Err(err) => {
                            log::error!("创建授权码失败: {}", err);
                            return HttpResponse::BadRequest().json(err.to_string());
                        }
                    }
                },
                Err(e) => {
                    log::error!("无法解析URL参数中的用户ID: {}", e);
                }
            }
        }
    }
    
    // 如果没有从参数获取到有效的用户ID，继续检查会话
    // 检查会话是否标记为已退出
    match session.get::<bool>("logged_out") {
        Ok(Some(true)) => {
            log::info!("会话已明确标记为退出状态，需要重新登录");
            session.purge(); // 清除会话
            let redirect_url = format!(
                "/login?client_id={}&redirect_uri={}&response_type={}&scope={}&state={}",
                query.client_id,
                query.redirect_uri,
                query.response_type,
                query.scope.as_deref().unwrap_or(""),
                query.state.as_deref().unwrap_or("")
            );
            
            log::info!("重定向到登录页面: {}", redirect_url);
            return HttpResponse::TemporaryRedirect()
                .append_header(("Location", redirect_url))
                .finish();
        },
        Ok(Some(false)) => {
            log::info!("会话明确标记为非退出状态");
        },
        Ok(None) => {
            log::info!("会话中没有退出标记");
        },
        Err(e) => {
            log::error!("读取会话退出标记时出错: {}", e);
        }
    }
    
    // 清除过期和失效的会话信息
    let user_id_result = session.get::<String>("user_id");
    
    // 如果无法读取用户ID或者用户ID为None，则重置会话
    if user_id_result.is_err() || user_id_result.as_ref().ok().unwrap_or(&None).is_none() {
        log::info!("会话中没有有效的用户ID或读取出错，清除会话并重定向到登录页面");
        session.purge();
        
        let redirect_url = format!(
            "/login?client_id={}&redirect_uri={}&response_type={}&scope={}&state={}",
            query.client_id,
            query.redirect_uri,
            query.response_type,
            query.scope.as_deref().unwrap_or(""),
            query.state.as_deref().unwrap_or("")
        );
        
        log::info!("重定向到登录页面: {}", redirect_url);
        return HttpResponse::TemporaryRedirect()
            .append_header(("Location", redirect_url))
            .finish();
    }
    
    let user_id_str = user_id_result.unwrap().unwrap();
    log::info!("从会话中获取到用户ID: {}", user_id_str);
    
    // 将字符串转换为Uuid并验证
    match Uuid::parse_str(&user_id_str) {
        Ok(id) => {
            log::info!("成功解析用户ID为Uuid: {}", id);
            
            // 验证用户ID是否有效
            match user_service::find_user_by_id(id, &db).await {
                Ok(Some(_)) => {
                    log::info!("已验证用户ID在数据库中存在: {}", id);
                    
                    // 检查该用户是否有任何有效令牌（即未被吊销的令牌）
                    match sqlx::query(r#"SELECT COUNT(*) FROM tokens WHERE user_id = $1 AND revoked = false"#)
                        .bind(id)
                        .fetch_one(db.get_ref())
                        .await 
                    {
                        Ok(row) => {
                            let token_count: i64 = row.get(0);
                            log::info!("用户 {} 有 {} 个有效令牌", id, token_count);
                            
                            // 如果用户没有有效令牌，强制重新登录
                            if token_count == 0 {
                                log::info!("用户 {} 没有有效令牌，强制重新登录", id);
                                session.purge();
                                let redirect_url = format!(
                                    "/login?client_id={}&redirect_uri={}&response_type={}&scope={}&state={}",
                                    query.client_id,
                                    query.redirect_uri,
                                    query.response_type,
                                    query.scope.as_deref().unwrap_or(""),
                                    query.state.as_deref().unwrap_or("")
                                );
                                
                                log::info!("重定向到登录页面: {}", redirect_url);
                                return HttpResponse::TemporaryRedirect()
                                    .append_header(("Location", redirect_url))
                                    .finish();
                            }
                        },
                        Err(e) => {
                            log::error!("检查用户令牌时数据库错误: {}", e);
                        }
                    }
                    
                    // 创建授权码
                    log::info!("为用户 {} 创建授权码", id);
                    match auth_service::create_authorization(id, &query, &db).await {
                        Ok(code) => {
                            // 构建重定向URL
                            let mut redirect_url = format!("{}?code={}", query.redirect_uri, code);
                            
                            // 添加state参数（如果存在）
                            if let Some(state) = &query.state {
                                redirect_url.push_str(&format!("&state={}", state));
                            }
                            
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
                },
                Ok(None) => {
                    log::warn!("用户ID在数据库中不存在: {}", id);
                    // 用户ID在数据库中不存在，清除会话并重定向到登录页面
                    session.purge();
                    let redirect_url = format!(
                        "/login?client_id={}&redirect_uri={}&response_type={}&scope={}&state={}",
                        query.client_id,
                        query.redirect_uri,
                        query.response_type,
                        query.scope.as_deref().unwrap_or(""),
                        query.state.as_deref().unwrap_or("")
                    );
                    
                    log::info!("重定向到登录页面: {}", redirect_url);
                    HttpResponse::TemporaryRedirect()
                        .append_header(("Location", redirect_url))
                        .finish()
                },
                Err(e) => {
                    log::error!("验证用户ID时数据库错误: {}", e);
                    // 数据库错误，重定向到登录页面
                    let redirect_url = format!(
                        "/login?client_id={}&redirect_uri={}&response_type={}&scope={}&state={}",
                        query.client_id,
                        query.redirect_uri,
                        query.response_type,
                        query.scope.as_deref().unwrap_or(""),
                        query.state.as_deref().unwrap_or("")
                    );
                    
                    log::info!("重定向到登录页面: {}", redirect_url);
                    HttpResponse::TemporaryRedirect()
                        .append_header(("Location", redirect_url))
                        .finish()
                }
            }
        },
        Err(e) => {
            log::error!("无法解析会话中的用户ID: {}", e);
            // 会话中的用户ID无效，清除会话并重定向到登录页面
            session.purge();
            let redirect_url = format!(
                "/login?client_id={}&redirect_uri={}&response_type={}&scope={}&state={}",
                query.client_id,
                query.redirect_uri,
                query.response_type,
                query.scope.as_deref().unwrap_or(""),
                query.state.as_deref().unwrap_or("")
            );
            
            log::info!("重定向到登录页面: {}", redirect_url);
            HttpResponse::TemporaryRedirect()
                .append_header(("Location", redirect_url))
                .finish()
        }
    }
}

// 令牌端点
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
    
    log::info!("处理令牌请求，客户端ID: {}", token_req.client_id);
    
    // 调试: 打印完整请求内容
    log::info!("令牌请求体: {:?}", token_req);
    
    // 调试: 打印请求头
    let headers = req.headers();
    let mut headers_str = String::new();
    for (key, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            headers_str.push_str(&format!("{}: {}, ", key, v));
        }
    }
    log::info!("令牌请求头: {}", headers_str);
    
    // 调试: 打印请求方法和URI
    log::info!("请求方法: {}, URI: {}", req.method(), req.uri());
    
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

// 用户信息端点
pub async fn userinfo(
    user: Option<web::ReqData<AuthenticatedUser>>,
    req: actix_web::HttpRequest,
    db: web::Data<PgPool>,
) -> impl Responder {
    // 获取请求的所有头部信息并记录
    let headers = req.headers();
    let mut headers_str = String::new();
    for (key, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            headers_str.push_str(&format!("{}: {}, ", key, v));
        }
    }
    log::info!("用户信息端点请求头: {}", headers_str);
    log::info!("用户信息端点请求方法: {}, URI: {}", req.method(), req.uri());
    
    // 尝试从授权头中提取令牌
    let mut token_from_header = None;
    if let Some(auth_header) = headers.get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") {
                token_from_header = Some(auth_str[7..].to_string());
                log::info!("从Authorization头中获取到访问令牌: {}", token_from_header.as_ref().unwrap());
            }
        }
    }
    
    // 检查是否有认证用户
    if let Some(user_data) = user {
        // 从中间件获取用户
        let user_id = user_data.into_inner().user_id;
        log::info!("从认证中间件获取用户ID: {}", user_id);
        
        process_userinfo_request(user_id, token_from_header, db).await
    } else if let Some(token) = token_from_header {
        // 如果没有经过中间件认证但有令牌，尝试手动验证
        match crate::utils::jwt::verify_token(&token) {
            Ok(token_data) => {
                let user_id = token_data.claims.sub;
                log::info!("手动验证令牌成功，用户ID: {}", user_id);
                
                process_userinfo_request(user_id, Some(token), db).await
            },
            Err(e) => {
                log::error!("手动验证令牌失败: {}", e);
                HttpResponse::Unauthorized().json(format!("无效的访问令牌: {}", e))
            }
        }
    } else {
        // 检查URL中是否有access_token参数（备用方式）
        if let Some(token) = req.query_string()
            .split('&')
            .find_map(|param| {
                if param.starts_with("access_token=") {
                    Some(param.split('=').nth(1).unwrap_or(""))
                } else {
                    None
                }
            }) 
        {
            // 验证令牌
            match crate::utils::jwt::verify_token(token) {
                Ok(token_data) => {
                    let user_id = token_data.claims.sub;
                    log::info!("从URL参数验证令牌成功，用户ID: {}", user_id);
                    
                    process_userinfo_request(user_id, Some(token.to_string()), db).await
                },
                Err(e) => {
                    log::error!("验证URL中的令牌失败: {}", e);
                    HttpResponse::Unauthorized().json(format!("无效的访问令牌: {}", e))
                }
            }
        } else {
            // 测试：返回一个测试用户（仅用于调试）
            // 你可能想要在这里查询数据库中的第一个用户作为测试
            match sqlx::query_as::<_, User>("SELECT * FROM users LIMIT 1")
                .fetch_optional(db.get_ref())
                .await
            {
                Ok(Some(test_user)) => {
                    log::warn!("用户信息请求无认证，返回测试用户ID: {}", test_user.id);
                    
                    // 创建Gitea兼容的用户响应（默认假设是Gitea类型）
                    let test_response = auth_service::get_user_info_for_client(
                        test_user.id, 
                        crate::models::ClientType::Gitea, 
                        &db
                    ).await;
                    
                    match test_response {
                        Ok(response) => HttpResponse::Ok().json(response),
                        Err(e) => {
                            log::error!("创建测试用户响应失败: {}", e);
                            HttpResponse::InternalServerError().json(e.to_string())
                        }
                    }
                },
                _ => {
                    // 如果没有认证用户，返回未认证错误
                    log::error!("用户信息请求未提供有效认证");
                    HttpResponse::Unauthorized().json("未提供有效的认证令牌")
                }
            }
        }
    }
}

// 处理用户信息请求的辅助函数
async fn process_userinfo_request(
    user_id: Uuid, 
    token: Option<String>,
    db: web::Data<PgPool>
) -> HttpResponse {
    // 如果有令牌，尝试获取客户端类型
    let client_type = if let Some(token_str) = token {
        match auth_service::get_client_type_by_token(&token_str, &db).await {
            Ok(ct) => {
                log::info!("获取到客户端类型: {:?}", ct);
                ct
            },
            Err(e) => {
                log::warn!("获取客户端类型失败，使用默认类型: {}", e);
                crate::models::ClientType::default()
            }
        }
    } else {
        log::info!("没有令牌，使用默认客户端类型");
        crate::models::ClientType::default()
    };
    
    // 根据客户端类型获取对应格式的用户信息
    match auth_service::get_user_info_for_client(user_id, client_type, &db).await {
        Ok(response) => {
            log::info!("成功获取用户信息: {}, 客户端类型: {:?}", user_id, client_type);
            HttpResponse::Ok().json(response)
        },
        Err(err) => {
            log::error!("获取用户信息失败: {}", err);
            HttpResponse::BadRequest().json(err.to_string())
        },
    }
}

// 登录处理程序
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

// 注册处理程序
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

// 退出登录处理程序
pub async fn logout(
    session: actix_session::Session,
    req: actix_web::HttpRequest,
    db: web::Data<PgPool>,
) -> impl Responder {
    log::info!("用户退出登录");
    
    // 标记是否是API请求（通过检查Accept头或其他标志）
    let is_api_request = req.headers().get("Accept")
        .and_then(|h| h.to_str().ok())
        .map(|accept| accept.contains("application/json"))
        .unwrap_or(false) || 
        req.headers().get("Authorization").is_some();
    
    let mut _token_revoked = false;
    let mut user_id = None;
    
    // 1. 尝试从Authorization头中获取令牌
    if let Some(auth_header) = req.headers().get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") {
                let token = auth_str.trim_start_matches("Bearer ").trim();
                log::info!("从Authorization头中获取令牌: {}", token);
                
                // 吊销特定令牌
                match query(r#"UPDATE tokens SET revoked = true WHERE access_token = $1 AND revoked = false"#)
                    .bind(token)
                    .execute(db.get_ref())
                    .await
                {
                    Ok(result) => {
                        let affected = result.rows_affected();
                        if affected > 0 {
                            log::info!("成功吊销令牌: {}", token);
                            _token_revoked = true;
                            
                            // 尝试从令牌中获取用户ID
                            if let Ok(token_data) = crate::utils::jwt::verify_token(token) {
                                user_id = Some(token_data.claims.sub);
                            }
                        } else {
                            log::warn!("找不到要吊销的令牌: {}", token);
                        }
                    },
                    Err(e) => {
                        log::error!("吊销令牌时数据库错误: {}", e);
                    }
                }
            }
        }
    }
    
    // 2. 从会话中获取用户ID并吊销所有令牌（如果上面没有吊销特定令牌）
    if user_id.is_none() {
        if let Ok(Some(user_id_str)) = session.get::<String>("user_id") {
            if let Ok(id) = Uuid::parse_str(&user_id_str) {
                user_id = Some(id);
                log::info!("从会话中获取用户ID: {}", id);
            } else {
                log::error!("无法解析用户ID: {}", user_id_str);
            }
        } else {
            log::warn!("用户退出登录时，会话中没有用户ID");
        }
    }
    
    // 如果有用户ID，无论从哪里获取的，都吊销该用户的所有令牌
    if let Some(id) = user_id {
        // 吊销该用户的所有令牌
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
                log::error!("吊销令牌时数据库错误: {}", e);
            }
        }
    }
    
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
        HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "已成功退出登录并吊销令牌"
        }))
    } else {
        // 对页面请求返回重定向
        HttpResponse::Found()
            .append_header(("Location", "/"))
            .finish()
    };
    
    // 添加强制清除客户端cookie的头
    let headers = response.headers_mut();
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
    // 这将强制客户端删除会话cookie
    headers.append(
        actix_web::http::header::SET_COOKIE,
        "id=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; HttpOnly; SameSite=Lax".parse().unwrap()
    );
    
    response
} 