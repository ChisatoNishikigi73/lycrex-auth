use actix_cors::Cors;
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::{
    get, http, middleware::Logger, post, web, App, HttpResponse, HttpServer, Responder, Result,
};
use dotenv::dotenv;
use log::{info, error};
use serde::{Deserialize, Serialize};
use std::env;
use std::time::Duration;
use chrono::{Utc, DateTime};
use serde_json;

// OAuth配置
const CLIENT_ID: &str = "test_client";
const CLIENT_SECRET: &str = "test_secret";
const REDIRECT_URI: &str = "http://localhost:3000/callback";
const AUTH_SERVER_URL: &str = "http://127.0.0.1:8080";

// 用户会话数据
#[derive(Serialize, Deserialize, Clone, Debug)]
struct UserSession {
    access_token: Option<String>,
    refresh_token: Option<String>,
    user_info: Option<UserInfo>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct UserInfo {
    id: String,
    username: String,
    email: String,
}

// OAuth相关请求和响应
#[derive(Deserialize)]
struct AuthCodeQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

// 添加错误响应结构体
#[derive(Deserialize, Debug)]
struct ErrorResponse {
    error: Option<String>,
    error_description: Option<String>,
    message: Option<String>,
}

#[derive(Serialize)]
struct TokenRequest {
    grant_type: String,
    code: String,
    redirect_uri: String,
    client_id: String,
    client_secret: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
    token_type: String,
}

// 在TokenResponse结构体中添加解析expires_at字段的函数
impl TokenResponse {
    fn expires_at(&self) -> DateTime<Utc> {
        Utc::now() + chrono::Duration::seconds(self.expires_in)
    }
}

// 添加刷新令牌请求结构
#[derive(Serialize)]
struct RefreshTokenRequest {
    grant_type: String,
    refresh_token: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
}

// 主页
#[get("/")]
async fn index(session: actix_session::Session) -> Result<impl Responder> {
    // 检查会话中是否有用户信息
    let user_session: Option<UserSession> = session.get("user")?;
    
    let html = match &user_session {
        Some(session) if session.user_info.is_some() => {
            let user = session.user_info.as_ref().unwrap();
            format!(
                r#"
                <!DOCTYPE html>
                <html>
                <head>
                    <title>测试客户端服务器</title>
                    <meta charset="UTF-8">
                    <style>
                        body {{ font-family: 'Segoe UI', Tahoma, Geneva, sans-serif; margin: 20px; line-height: 1.5; color: #333; }}
                        .container {{ max-width: 800px; margin: 0 auto; }}
                        .card {{ background: #fff; border: 1px solid #e0e0e0; padding: 15px; margin-bottom: 15px; }}
                        button, a.button {{ background: #2c3e50; color: white; padding: 8px 12px; border: none; cursor: pointer; text-decoration: none; display: inline-block; font-size: 14px; }}
                        button:hover, a.button:hover {{ background: #1a252f; }}
                        pre {{ background: #f8f8f8; padding: 10px; border: 1px solid #e0e0e0; font-size: 13px; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>测试客户端服务器</h1>
                        <div class="card">
                            <h2>已登录用户信息</h2>
                            <p><strong>用户ID:</strong> {}</p>
                            <p><strong>用户名:</strong> {}</p>
                            <p><strong>邮箱:</strong> {}</p>
                            <form action="/logout" method="post">
                                <button type="submit">退出登录</button>
                            </form>
                        </div>
                        <div class="card">
                            <h2>访问令牌信息</h2>
                            <pre>{}</pre>
                            <pre>{}</pre>
                        </div>
                        <div class="card">
                            <h2>令牌测试功能</h2>
                            <button id="checkToken" type="button">检查令牌有效性</button>
                            <p id="tokenStatus"></p>
                            <div id="spinner" style="display:none;">检查中...</div>
                            <div id="reloginContainer" style="display:none; margin-top: 10px;">
                                <p>令牌已过期，需要重新登录</p>
                                <form action="/logout" method="post">
                                    <button type="submit">重新登录</button>
                                </form>
                            </div>
                        </div>
                        <script>
                            document.getElementById('checkToken').addEventListener('click', async function() {{
                                document.getElementById('tokenStatus').textContent = '';
                                document.getElementById('spinner').style.display = 'block';
                                document.getElementById('reloginContainer').style.display = 'none';
                                
                                try {{
                                    const response = await fetch('/check-token');
                                    const text = await response.text();
                                    
                                    if (response.ok) {{
                                        document.getElementById('tokenStatus').textContent = '✅ ' + text;
                                    }} else {{
                                        document.getElementById('tokenStatus').textContent = '❌ ' + text;
                                        // 检查是否包含过期或重新登录字样
                                        if (text.includes('过期') || text.includes('重新登录') || response.status === 401) {{
                                            document.getElementById('reloginContainer').style.display = 'block';
                                        }}
                                    }}
                                }} catch (error) {{
                                    document.getElementById('tokenStatus').textContent = '❌ 请求失败: ' + error;
                                }} finally {{
                                    document.getElementById('spinner').style.display = 'none';
                                }}
                            }});
                        </script>
                    </div>
                </body>
                </html>
                "#,
                user.id,
                user.username,
                user.email,
                session.access_token.as_ref().unwrap_or(&"无访问令牌".to_string()),
                session.refresh_token.as_ref().unwrap_or(&"无刷新令牌".to_string())
            )
        }
        _ => {
            // 构建OAuth授权URL
            let authorize_url = format!(
                "{}/api/oauth/authorize?response_type=code&client_id={}&redirect_uri={}",
                AUTH_SERVER_URL, CLIENT_ID, REDIRECT_URI
            );

            format!(
                r#"
                <!DOCTYPE html>
                <html>
                <head>
                    <title>测试客户端服务器</title>
                    <meta charset="UTF-8">
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }}
                        .container {{ max-width: 800px; margin: 0 auto; }}
                        .card {{ background: #f9f9f9; border-radius: 5px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                        a.button {{ background: #4CAF50; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }}
                        a.button:hover {{ background: #45a049; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>测试客户端服务器</h1>
                        <div class="card">
                            <h2>OAuth授权测试</h2>
                            <p>请点击下方按钮使用OAuth登录：</p>
                            <a href="{}" class="button">使用OAuth登录</a>
                        </div>
                    </div>
                </body>
                </html>
                "#,
                authorize_url
            )
        }
    };

    Ok(HttpResponse::Ok().content_type("text/html").body(html))
}

// OAuth回调处理
#[get("/callback")]
async fn callback(
    query: web::Query<AuthCodeQuery>,
    session: actix_session::Session,
) -> Result<impl Responder> {
    // 检查是否有错误
    if let Some(error) = &query.error {
        error!("授权错误: {}", error);
        return Ok(HttpResponse::BadRequest().body(format!("授权错误: {}", error)));
    }

    // 获取授权码
    let code = match &query.code {
        Some(code) => code,
        None => return Ok(HttpResponse::BadRequest().body("未收到授权码")),
    };

    info!("收到授权码: {}", code);

    // 交换授权码获取令牌
    let client = reqwest::Client::new();
    let token_url = format!("{}/api/oauth/token", AUTH_SERVER_URL);
    
    let token_request = TokenRequest {
        grant_type: "authorization_code".to_string(),
        code: code.clone(),
        redirect_uri: REDIRECT_URI.to_string(),
        client_id: CLIENT_ID.to_string(),
        client_secret: CLIENT_SECRET.to_string(),
    };

    // 发送令牌请求
    let response = match client.post(&token_url).json(&token_request).send().await {
        Ok(response) => response,
        Err(e) => {
            error!("发送令牌请求失败: {}", e);
            return Ok(HttpResponse::InternalServerError().body(format!("发送令牌请求失败: {}", e)));
        }
    };
    
    let status = response.status();
    if !status.is_success() {
        let error_text = response.text().await.unwrap_or_else(|_| "无法读取错误信息".to_string());
        error!("令牌请求失败，状态码: {}，响应: {}", status, error_text);
        return Ok(HttpResponse::InternalServerError().body(format!("令牌请求失败: {}", error_text)));
    }

    let token_response = match response.json::<TokenResponse>().await {
        Ok(token) => token,
        Err(e) => {
            error!("解析令牌响应失败: {}", e);
            return Ok(HttpResponse::InternalServerError().body(format!("解析令牌响应失败: {}", e)));
        }
    };

    info!("获取到访问令牌: {}", token_response.access_token);
    info!("获取到刷新令牌: {}", token_response.refresh_token);

    // 获取用户信息
    let user_info_url = format!("{}/api/oauth/userinfo", AUTH_SERVER_URL);
    let user_response = match client
        .get(&user_info_url)
        .header(
            http::header::AUTHORIZATION,
            format!("Bearer {}", token_response.access_token),
        )
        .send()
        .await
    {
        Ok(response) => response,
        Err(e) => {
            error!("发送用户信息请求失败: {}", e);
            return Ok(HttpResponse::InternalServerError().body(format!("发送用户信息请求失败: {}", e)));
        }
    };
    
    let user_status = user_response.status();
    if !user_status.is_success() {
        let error_text = user_response.text().await.unwrap_or_else(|_| "无法读取错误信息".to_string());
        error!("获取用户信息失败，状态码: {}，响应: {}", user_status, error_text);
        return Ok(HttpResponse::InternalServerError().body(format!("获取用户信息失败: {}", error_text)));
    }

    let user_info = match user_response.json::<UserInfo>().await {
        Ok(user) => user,
        Err(e) => {
            error!("解析用户信息失败: {}", e);
            return Ok(HttpResponse::InternalServerError().body(format!("解析用户信息失败: {}", e)));
        }
    };

    info!("获取到用户信息: id={}, username={}, email={}", user_info.id, user_info.username, user_info.email);

    // 保存用户信息到会话
    let user_session = UserSession {
        access_token: Some(token_response.access_token),
        refresh_token: Some(token_response.refresh_token),
        user_info: Some(user_info),
    };

    match session.insert("user", user_session) {
        Ok(_) => {
            info!("已将用户会话信息保存到会话中");
            // 重定向到主页
            Ok(HttpResponse::Found().append_header((http::header::LOCATION, "/")).finish())
        },
        Err(e) => {
            error!("保存会话信息失败: {}", e);
            Ok(HttpResponse::InternalServerError().body(format!("保存会话信息失败: {}", e)))
        }
    }
}

// 退出登录
#[post("/logout")]
async fn logout(session: actix_session::Session) -> impl Responder {
    // 获取会话中的用户信息
    let user_session: Option<UserSession> = session.get("user").unwrap_or(None);
    
    // 准备响应
    let mut response = HttpResponse::Found()
        .append_header((http::header::LOCATION, "/"))
        .finish();
    
    if let Some(user_session) = user_session {
        // 如果有访问令牌，调用认证服务器的logout API
        if let Some(access_token) = user_session.access_token {
            info!("尝试调用认证服务器吊销令牌");
            
            // 创建HTTP客户端
            let client = reqwest::Client::builder()
                .cookie_store(true) // 启用cookie存储
                .build()
                .unwrap_or_default();
                
            let logout_url = format!("{}/api/auth/logout", AUTH_SERVER_URL);
            
            // 发送带有令牌的POST请求到认证服务器的logout端点
            match client
                .post(&logout_url)
                .header(
                    http::header::AUTHORIZATION,
                    format!("Bearer {}", access_token),
                )
                .send()
                .await
            {
                Ok(auth_response) => {
                    info!("已发送退出登录请求到认证服务器");
                    
                    // 检查并应用认证服务器设置的任何cookies
                    let cookies = auth_response.headers().get_all(http::header::SET_COOKIE);
                    for cookie in cookies {
                        if let Ok(cookie_str) = cookie.to_str() {
                            info!("从认证服务器接收到cookie: {}", cookie_str);
                            response.headers_mut().append(
                                http::header::SET_COOKIE,
                                cookie.clone()
                            );
                        }
                    }
                },
                Err(e) => {
                    // 连接错误可能是因为服务器在返回302重定向时关闭了连接
                    // 这种情况下通常令牌仍然被吊销了
                    error!("发送退出登录请求时出现错误: {}", e);
                    info!("尽管有错误，令牌可能已被成功吊销");
                }
            }
        }
    }
    
    // 清除本地会话
    session.remove("user");
    
    // 添加强制清除cookie头
    response.headers_mut().append(
        http::header::CACHE_CONTROL,
        "no-store, must-revalidate, max-age=0".parse().unwrap()
    );
    
    response
}

// 添加检查令牌页面和接口
#[get("/check-token")]
async fn check_token(session_data: actix_session::Session) -> Result<impl Responder> {
    let user_session: Option<UserSession> = session_data.get("user")?;
    
    if let Some(session) = user_session {
        let access_token = match &session.access_token {
            Some(token) => token.clone(),
            None => return Ok(HttpResponse::BadRequest().body("没有访问令牌"))
        };
        
        // 创建HTTP客户端
        let client = reqwest::Client::new();
        
        // 调用userinfo端点检查令牌
        let user_info_url = format!("{}/api/oauth/userinfo", AUTH_SERVER_URL);
        let response = match client
            .get(&user_info_url)
            .header(http::header::AUTHORIZATION, format!("Bearer {}", access_token))
            .timeout(Duration::from_secs(5))
            .send()
            .await 
        {
            Ok(response) => response,
            Err(e) => {
                error!("令牌检查请求失败: {}", e);
                return Ok(HttpResponse::InternalServerError().body(format!("令牌检查请求失败: {}", e)));
            }
        };
        
        // 检查响应状态
        let status = response.status();
        
        // 添加日志，显示响应状态
        info!("令牌检查响应状态: {}", status);
        
        if status.is_success() {
            // 成功响应 - 令牌有效
            return Ok(HttpResponse::Ok().body("令牌有效，成功获取用户信息"));
        } else {
            // 如果令牌无效，尝试使用刷新令牌
            let error_text = response.text().await.unwrap_or_else(|_| "无法读取错误信息".to_string());
            error!("令牌无效，状态码: {}，响应: {}", status, error_text);
            
            // 检查是否有刷新令牌
            if let Some(refresh_token) = &session.refresh_token {
                info!("尝试使用刷新令牌获取新的访问令牌: {}", refresh_token);
                
                // 发送刷新令牌请求
                let token_url = format!("{}/api/oauth/token", AUTH_SERVER_URL);
                info!("发送刷新令牌请求到: {}", token_url);
                
                let refresh_request = RefreshTokenRequest {
                    grant_type: "refresh_token".to_string(),
                    refresh_token: refresh_token.clone(),
                    client_id: CLIENT_ID.to_string(),
                    client_secret: CLIENT_SECRET.to_string(),
                    redirect_uri: REDIRECT_URI.to_string(),
                };
                
                info!("刷新令牌请求内容: client_id={}, grant_type={}", 
                      refresh_request.client_id, 
                      refresh_request.grant_type);
                
                let refresh_response = match client.post(&token_url)
                    .json(&refresh_request)
                    .send()
                    .await 
                {
                    Ok(response) => response,
                    Err(e) => {
                        error!("刷新令牌请求失败: {}", e);
                        return Ok(HttpResponse::InternalServerError().body(format!("刷新令牌请求失败: {}", e)));
                    }
                };
                
                // 记录刷新响应的状态码
                let refresh_status = refresh_response.status();
                info!("刷新令牌响应状态码: {}", refresh_status);
                
                if refresh_status.is_success() {
                    // 成功获取新令牌
                    let token_response = match refresh_response.json::<TokenResponse>().await {
                        Ok(token) => token,
                        Err(e) => {
                            error!("解析刷新令牌响应失败: {}", e);
                            return Ok(HttpResponse::InternalServerError().body(format!("解析刷新令牌响应失败: {}", e)));
                        }
                    };
                    
                    info!("成功刷新令牌，新的访问令牌: {}", token_response.access_token);
                    
                    // 更新会话中的令牌
                    let mut updated_session = session.clone();
                    updated_session.access_token = Some(token_response.access_token);
                    updated_session.refresh_token = Some(token_response.refresh_token);
                    
                    match session_data.insert("user", updated_session) {
                        Ok(_) => {
                            info!("成功更新会话中的令牌");
                            return Ok(HttpResponse::Ok().body("令牌已成功刷新"));
                        },
                        Err(e) => {
                            error!("更新会话令牌失败: {}", e);
                            return Ok(HttpResponse::InternalServerError().body(format!("更新会话令牌失败: {}", e)));
                        }
                    }
                } else {
                    // 刷新令牌也无效
                    let status = refresh_status;
                    
                    // 尝试解析错误响应为JSON
                    let error_body = refresh_response.text().await.unwrap_or_else(|_| "无法读取错误信息".to_string());
                    let parsed_error = match serde_json::from_str::<ErrorResponse>(&error_body) {
                        Ok(err) => {
                            let err_msg = match (err.error.as_deref(), err.error_description.as_deref(), err.message.as_deref()) {
                                (Some(e), Some(desc), _) => format!("错误: {} - {}", e, desc),
                                (Some(e), None, Some(msg)) => format!("错误: {} - {}", e, msg),
                                (Some(e), None, None) => format!("错误: {}", e),
                                (None, None, Some(msg)) => format!("错误: {}", msg),
                                _ => error_body.clone(),
                            };
                            error!("解析到的错误信息: {:?}", err);
                            err_msg
                        },
                        Err(_) => {
                            error!("无法解析错误响应为JSON: {}", error_body);
                            error_body.clone()
                        }
                    };
                    
                    error!("刷新令牌无效，状态码: {}，响应: {}", status, error_body);
                    
                    // 如果刷新令牌失败，清除会话并返回建议重新登录的消息
                    session_data.remove("user");
                    info!("已清除会话，用户需要重新登录");
                    
                    return Ok(HttpResponse::Unauthorized()
                        .body(format!("令牌已过期且刷新失败: {}。请重新登录。", parsed_error)));
                }
            } else {
                // 没有刷新令牌
                info!("没有刷新令牌可用，需要重新登录");
                return Ok(HttpResponse::Unauthorized().body("令牌无效且没有刷新令牌。请重新登录。"));
            }
        }
    } else {
        // 会话中没有用户信息
        Ok(HttpResponse::Unauthorized().body("未登录，没有令牌"))
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // 加载环境变量
    dotenv().ok();
    
    // 初始化日志
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));
    
    // 服务器配置
    let host = env::var("CLIENT_SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = env::var("CLIENT_SERVER_PORT").unwrap_or_else(|_| "3000".to_string());
    let server_url = format!("http://{}:{}", host, port);
    
    info!("🚀 启动测试客户端服务器, 监听地址: {}:{}", host, port);
    info!("服务器URL: {}", server_url);
    info!("授权服务器URL: {}", AUTH_SERVER_URL);
    info!("OAuth重定向URI: {}", REDIRECT_URI);
    
    HttpServer::new(move || {
        // 配置CORS
        let cors = Cors::default()
            .allowed_origin("http://localhost:3000")
            .allowed_origin(AUTH_SERVER_URL)
            .allowed_methods(vec!["GET", "POST"])
            .allowed_headers(vec![http::header::AUTHORIZATION, http::header::CONTENT_TYPE])
            .max_age(3600);
            
        // 会话密钥 - 必须足够长（至少64字节）
        let secret_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let session_key = actix_web::cookie::Key::from(secret_key.as_bytes());
            
        App::new()
            .wrap(Logger::default())
            .wrap(cors)
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), session_key.clone())
                    .cookie_secure(false) // 开发环境设置为false
                    .build(),
            )
            .service(index)
            .service(callback)
            .service(logout)
            .service(check_token)
    })
    .bind(format!("{}:{}", host, port))?
    .run()
    .await
} 