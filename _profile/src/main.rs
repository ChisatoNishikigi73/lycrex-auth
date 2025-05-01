use actix_files::Files;
use actix_web::{
    cookie::Cookie,
    get, http, middleware, web, App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use dotenv::dotenv;
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::env;
use tera::{Context, Tera};

// 用户信息结构体
#[derive(Debug, Clone, Serialize, Deserialize)]
struct User {
    #[serde(rename = "id")]
    id: String,
    #[serde(rename = "preferred_username")]
    username: String,
    #[serde(rename = "email")]
    email: String,
    #[serde(rename = "email_verified")]
    email_verified: bool,
    #[serde(rename = "avatar_url", default)]
    avatar_url: Option<String>,
    #[serde(rename = "avatar", default)]
    avatar: Option<String>,
    #[serde(rename = "picture", default)]
    picture: Option<String>,
    #[serde(rename = "created_at")]
    created_at: String,
    #[serde(rename = "last_login_at", default)]
    last_login_at: Option<String>,
    #[serde(rename = "is_active", default = "default_is_active")]
    is_active: bool,
    #[serde(rename = "recent_login_count", default)]
    recent_login_count: Option<i64>,
}

// 默认值函数
fn default_is_active() -> bool {
    true
}

// OAuth客户端配置
struct OAuthConfig {
    auth_server_url: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
}

// 获取环境变量，如果不存在则使用默认值
fn get_env_or_default(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

// 初始化OAuth配置
fn init_oauth_config() -> OAuthConfig {
    OAuthConfig {
        auth_server_url: get_env_or_default("AUTH_SERVER_URL", "http://127.0.0.1:8080"),
        client_id: get_env_or_default("CLIENT_ID", "profile-client"),
        client_secret: get_env_or_default("CLIENT_SECRET", "profile-secret"),
        redirect_uri: get_env_or_default("REDIRECT_URI", "http://localhost:3000/callback"),
    }
}

// 首页路由
#[get("/")]
async fn index(
    req: HttpRequest,
    tmpl: web::Data<tera::Tera>,
    oauth_config: web::Data<OAuthConfig>,
) -> impl Responder {
    // 检查是否已经登录（通过access_token cookie判断）
    if let Some(_token) = req.cookie("access_token") {
        // 如果有token，重定向到profile页面
        return HttpResponse::Found()
            .append_header((http::header::LOCATION, "/profile"))
            .finish();
    }

    // 构建OAuth登录URL
    let oauth_url = format!(
        "{}/api/oauth/authorize?response_type=lycrex&client_id={}&redirect_uri={}",
        oauth_config.auth_server_url, oauth_config.client_id, oauth_config.redirect_uri
    );

    let mut context = Context::new();
    context.insert("oauth_url", &oauth_url);

    // 渲染登录页面
    match tmpl.render("login.html", &context) {
        Ok(s) => HttpResponse::Ok().content_type("text/html").body(s),
        Err(e) => {
            error!("模板渲染错误: {}", e);
            HttpResponse::InternalServerError().body("模板渲染错误")
        }
    }
}

// 用于OAuth回调的路由
#[get("/callback")]
async fn oauth_callback(
    req: HttpRequest,
    oauth_config: web::Data<OAuthConfig>,
    client: web::Data<reqwest::Client>,
) -> impl Responder {
    // 从查询参数中提取授权码
    let query_params = req.query_string();
    
    // 获取授权码参数
    let code = web::Query::<std::collections::HashMap<String, String>>::from_query(query_params)
        .map(|q| q.get("code").cloned())
        .ok()
        .flatten();

    // 如果授权码不存在，则重定向到登录页面
    let code = match code {
        Some(code) => code,
        None => {
            error!("回调请求中没有授权码");
            return HttpResponse::Found()
                .append_header((http::header::LOCATION, "/?error=no_code"))
                .finish()
        }
    };

    info!("收到授权码: {}", code);

    // 使用授权码获取访问令牌
    let token_response = match exchange_code_for_token(&client, &oauth_config, &code).await {
        Ok(token) => token,
        Err(e) => {
            error!("获取令牌失败: {}", e);
            return HttpResponse::Found()
                .append_header((http::header::LOCATION, "/?error=token_error"))
                .finish();
        }
    };

    info!("成功交换授权码获取访问令牌");

    // 使用访问令牌获取用户信息
    let user_info = match get_user_info(&client, &oauth_config, &token_response.access_token).await
    {
        Ok(user) => {
            info!("成功获取用户信息: {}", user.username);
            user
        },
        Err(e) => {
            error!("获取用户信息失败: {}", e);
            return HttpResponse::Found()
                .append_header((http::header::LOCATION, "/?error=userinfo_error"))
                .finish();
        }
    };

    // 创建访问令牌cookie，用于后续请求
    let token_cookie = Cookie::build("access_token", token_response.access_token)
        .path("/")
        .http_only(true)
        .max_age(actix_web::cookie::time::Duration::seconds(token_response.expires_in))
        .finish();

    // 创建用户信息cookie，用于显示用户资料
    let user_cookie = Cookie::build("user_info", serde_json::to_string(&user_info).unwrap())
        .path("/")
        .http_only(true)
        .max_age(actix_web::cookie::time::Duration::seconds(token_response.expires_in))
        .finish();

    // 重定向到profile页面，并设置cookie
    HttpResponse::Found()
        .cookie(token_cookie)
        .cookie(user_cookie)
        .append_header((http::header::LOCATION, "/profile"))
        .finish()
}

// 获取用户信息API
#[get("/api/userinfo")]
async fn get_user_info_api(
    req: HttpRequest, 
    client: web::Data<reqwest::Client>,
    oauth_config: web::Data<OAuthConfig>,
) -> impl Responder {
    // 检查是否已登录
    let access_token = match req.cookie("access_token") {
        Some(cookie) => cookie.value().to_string(),
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "未登录或会话已过期"
            }));
        }
    };

    // 获取用户信息
    let user_info_url = format!("{}/api/oauth/userinfo", oauth_config.auth_server_url);

    let response = match client
        .get(&user_info_url)
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await {
            Ok(resp) => resp,
            Err(e) => {
                error!("请求用户信息失败: {}", e);
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "获取用户信息失败"
                }));
            }
        };

    if !response.status().is_success() {
        let error_text = response.text().await.unwrap_or_default();
        error!("获取用户信息响应错误: {}", error_text);
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "获取用户信息失败"
        }));
    }

    // 获取原始JSON响应
    match response.text().await {
        Ok(text) => {
            // 尝试解析为JSON以确保是有效的JSON
            match serde_json::from_str::<serde_json::Value>(&text) {
                Ok(json_value) => HttpResponse::Ok().json(json_value),
                Err(e) => {
                    error!("解析响应JSON失败: {}", e);
                    HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": "无效的JSON响应"
                    }))
                }
            }
        },
        Err(e) => {
            error!("读取响应内容失败: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "读取响应失败"
            }))
        }
    }
}

// 个人资料页面路由
#[get("/profile")]
async fn profile(tmpl: web::Data<tera::Tera>) -> impl Responder {
    // 不再从Cookie读取用户信息，而是先返回页面，让JavaScript获取数据
    let context = Context::new();
    
    // 渲染个人资料页面
    match tmpl.render("profile.html", &context) {
        Ok(s) => HttpResponse::Ok().content_type("text/html").body(s),
        Err(e) => {
            error!("模板渲染错误: {}", e);
            HttpResponse::InternalServerError().body("模板渲染错误")
        }
    }
}

// 登出路由
#[get("/logout")]
async fn logout() -> impl Responder {
    // 清除cookie并重定向到登录页面
    HttpResponse::Found()
        .cookie(
            Cookie::build("access_token", "")
                .path("/")
                .max_age(actix_web::cookie::time::Duration::seconds(0))
                .finish(),
        )
        .cookie(
            Cookie::build("user_info", "")
                .path("/")
                .max_age(actix_web::cookie::time::Duration::seconds(0))
                .finish(),
        )
        .append_header((http::header::LOCATION, "/"))
        .finish()
}

// OAuth令牌响应
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
    #[serde(default)]
    refresh_token: Option<String>,
}

// 使用授权码获取访问令牌
async fn exchange_code_for_token(
    client: &reqwest::Client,
    config: &OAuthConfig,
    code: &str,
) -> Result<TokenResponse, String> {
    let token_url = format!("{}/api/oauth/token", config.auth_server_url);

    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("client_id", &config.client_id),
        ("client_secret", &config.client_secret),
        ("redirect_uri", &config.redirect_uri),
    ];

    let response = client
        .post(&token_url)
        .form(&params)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !response.status().is_success() {
        let error_text = response.text().await.unwrap_or_default();
        return Err(format!("令牌请求失败: {}", error_text));
    }

    response.json::<TokenResponse>().await.map_err(|e| e.to_string())
}

// 获取用户信息
async fn get_user_info(
    client: &reqwest::Client,
    config: &OAuthConfig,
    token: &str,
) -> Result<User, String> {
    let user_info_url = format!("{}/api/oauth/userinfo", config.auth_server_url);

    let response = client
        .get(&user_info_url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !response.status().is_success() {
        let error_text = response.text().await.unwrap_or_default();
        return Err(format!("获取用户信息失败: {}", error_text));
    }

    // 先获取响应文本以便调试
    let response_text = response.text().await.map_err(|e| e.to_string())?;
    info!("用户信息原始响应: {}", response_text);
    
    // 尝试解析用户信息
    match serde_json::from_str::<User>(&response_text) {
        Ok(user) => Ok(user),
        Err(e) => {
            error!("用户信息解析错误: {}", e);
            error!("收到的响应内容: {}", response_text);
            
            // 尝试使用更宽松的解析方式
            let json_value: serde_json::Value = serde_json::from_str(&response_text)
                .map_err(|e| format!("JSON解析失败: {}", e))?;
            
            // 详细记录JSON结构
            info!("JSON字段: {:?}", json_value.as_object().map(|obj| obj.keys().collect::<Vec<_>>()));
            
            // 尝试不同的用户名字段
            let username = json_value.get("username")
                .or_else(|| json_value.get("name"))
                .or_else(|| json_value.get("preferred_username"))
                .or_else(|| json_value.get("login"))
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            
            info!("提取的用户名: {}", username);
            
            // 手动构建User对象
            let user = User {
                id: json_value.get("id").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
                username,
                email: json_value.get("email").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
                email_verified: json_value.get("email_verified").and_then(|v| v.as_bool()).unwrap_or(false),
                avatar_url: json_value.get("avatar_url")
                    .or_else(|| json_value.get("avatar"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                avatar: json_value.get("avatar").and_then(|v| v.as_str()).map(|s| s.to_string()),
                picture: json_value.get("picture").and_then(|v| v.as_str()).map(|s| s.to_string()),
                created_at: json_value.get("created_at").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
                last_login_at: json_value.get("last_login_at")
                    .or_else(|| json_value.get("last_login"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                is_active: json_value.get("is_active").and_then(|v| v.as_bool()).unwrap_or(true),
                recent_login_count: json_value.get("recent_login_count").and_then(|v| v.as_i64()),
            };
            
            info!("手动解析后的用户信息: {:?}", user);
            Ok(user)
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // 加载环境变量
    dotenv().ok();
    
    // 初始化日志
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));
    
    // 获取服务器地址和端口
    let host = get_env_or_default("HOST", "127.0.0.1");
    let port = get_env_or_default("PORT", "3000").parse::<u16>().unwrap_or(3000);
    
    // 初始化OAuth配置
    let oauth_config = init_oauth_config();
    info!("OAuth重定向URI: {}", oauth_config.redirect_uri);
    
    // 创建HTTP客户端
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap();

    // 启动服务器
    info!("启动服务器，监听地址: {}:{}", host, port);
    HttpServer::new(move || {
        // 初始化模板系统
        let mut tera = Tera::new("src/templates/**/*").unwrap();
        tera.autoescape_on(vec!["html"]);
        
        App::new()
            .wrap(middleware::Logger::default())
            .app_data(web::Data::new(tera))
            .app_data(web::Data::new(oauth_config.clone()))
            .app_data(web::Data::new(client.clone()))
            .service(index)
            .service(oauth_callback)
            .service(profile)
            .service(logout)
            .service(get_user_info_api)
            .service(get_recent_clients)
            .service(Files::new("/static", "src/static"))
    })
    .bind((host, port))?
    .run()
    .await
}

// 为OAuthConfig实现Clone特性
impl Clone for OAuthConfig {
    fn clone(&self) -> Self {
        Self {
            auth_server_url: self.auth_server_url.clone(),
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            redirect_uri: self.redirect_uri.clone(),
        }
    }
}
