use crate::{config::OAuthConfig, models::ProcessedCodes, utils};
use actix_web::{
    cookie::Cookie,
    get, http, post, web, HttpRequest, HttpResponse, Responder,
};
use actix_multipart::Multipart;
use futures::StreamExt;
use log::{error, info};
use serde_json;
use std::sync::Mutex;

/// 首页路由
#[get("")]
pub async fn index(
    req: HttpRequest,
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
    
    // 检查查询参数中是否有错误信息
    let query = req.query_string();
    let error_type = if query.contains("error=session_expired") {
        "session_expired"
    } else if query.contains("error=token_error") {
        "token_error"
    } else if query.contains("error=userinfo_error") {
        "userinfo_error" 
    } else if query.contains("error=no_code") {
        "no_code"
    } else {
        ""
    };
    
    let error_message = if !error_type.is_empty() {
        match error_type {
            "session_expired" => "您的会话已过期，请重新登录",
            "token_error" => "获取授权令牌失败，请重试",
            "userinfo_error" => "获取用户信息失败，请重试",
            "no_code" => "未收到授权码，请重试",
            _ => "登录过程中发生未知错误，请重试"
        }
    } else {
        ""
    };

    // 获取HTML模板
    let mut html = include_str!("templates/login.html").to_string();
    
    // 替换模板变量
    html = html.replace("{{ oauth_url }}", &oauth_url);
    
    // 如果有错误信息，添加错误提示脚本
    if !error_message.is_empty() {
        let error_script = format!(
            r#"<script>
                document.addEventListener('DOMContentLoaded', function() {{
                    document.getElementById('error').textContent = "{}";
                    document.getElementById('error').style.display = 'block';
                }});
            </script>"#,
            error_message
        );
        html = html.replace("</body>", &format!("{}\n</body>", error_script));
    }
    
    HttpResponse::Ok().content_type("text/html").body(html)
}

/// 用于OAuth回调的路由
#[get("callback")]
pub async fn oauth_callback(
    req: HttpRequest,
    oauth_config: web::Data<OAuthConfig>,
    client: web::Data<reqwest::Client>,
    processed_codes: web::Data<Mutex<ProcessedCodes>>,
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
                .append_header((http::header::LOCATION, "/auth?error=no_code"))
                .finish();
        }
    };

    // 检查授权码是否已经处理过，防止重复处理
    {
        let mut codes = processed_codes.lock().unwrap();
        if codes.codes.contains(&code) {
            info!("授权码已被处理，显示处理中页面");
            // 返回一个简单的HTML页面，显示处理中并自动重定向到首页
            let html = r#"
                <!DOCTYPE html>
                <html>
                <head>
                    <title>处理中</title>
                    <meta http-equiv="refresh" content="2;url=/profile">
                    <style>
                        body { font-family: Arial, sans-serif; text-align: center; margin-top: 100px; }
                        .loader { border: 5px solid #f3f3f3; border-top: 5px solid #3498db; border-radius: 50%; width: 50px; height: 50px; animation: spin 1s linear infinite; margin: 20px auto; }
                        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
                    </style>
                </head>
                <body>
                    <h2>登录成功，正在跳转...</h2>
                    <div class="loader"></div>
                    <p>如果页面没有自动跳转，请<a href="/profile">点击这里</a></p>
                </body>
                </html>
            "#;
            return HttpResponse::Ok()
                .content_type("text/html; charset=utf-8")
                .body(html);
        }
        
        // 记录此授权码已经开始处理
        codes.codes.insert(code.clone());
    }

    info!("收到授权码: {}", code);
    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;

    // 使用授权码获取访问令牌
    match utils::get_token_with_code(&client, &oauth_config, &code).await {
        Ok(token) => {
            info!("成功获取访问令牌");
            
            // 使用访问令牌获取用户信息
            match utils::get_user_info(&client, &oauth_config, &token.access_token).await {
                Ok(user) => {
                    info!("成功获取用户信息: {}", user.username);
                    
                    // 创建访问令牌cookie
                    let token_cookie = Cookie::build("access_token", token.access_token)
                        .path("/")
                        .http_only(true)
                        .max_age(actix_web::cookie::time::Duration::seconds(token.expires_in))
                        .finish();

                    // 创建用户信息cookie
                    let user_cookie = Cookie::build("user_info", serde_json::to_string(&user).unwrap())
                        .path("/")
                        .http_only(true)
                        .max_age(actix_web::cookie::time::Duration::seconds(token.expires_in))
                        .finish();

                    // 返回处理中的HTML页面而不是立即重定向
                    let html = r#"
                        <!DOCTYPE html>
                        <html>
                        <head>
                            <title>登录成功</title>
                            <meta http-equiv="refresh" content="2;url=/profile">
                            <style>
                                body { font-family: Arial, sans-serif; text-align: center; margin-top: 100px; }
                                .loader { border: 5px solid #f3f3f3; border-top: 5px solid #3498db; border-radius: 50%; width: 50px; height: 50px; animation: spin 1s linear infinite; margin: 20px auto; }
                                @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
                            </style>
                        </head>
                        <body>
                            <h2>登录成功，正在跳转...</h2>
                            <div class="loader"></div>
                            <p>如果页面没有自动跳转，请<a href="/profile">点击这里</a></p>
                        </body>
                        </html>
                    "#;
                    
                    HttpResponse::Ok()
                        .cookie(token_cookie)
                        .cookie(user_cookie)
                        .content_type("text/html; charset=utf-8")
                        .body(html)
                },
                Err(e) => {
                    error!("获取用户信息失败: {}", e);
                    HttpResponse::Found()
                        .append_header((http::header::LOCATION, "/auth?error=userinfo_error"))
                        .finish()
                }
            }
        },
        Err(e) => {
            error!("获取令牌失败: {}", e);
            HttpResponse::Found()
                .append_header((http::header::LOCATION, "/auth?error=token_error"))
                .finish()
        }
    }
}

/// 处理头像上传的API
#[post("/api/upload-avatar")]
pub async fn upload_avatar(
    req: HttpRequest,
    mut payload: Multipart,
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

    // 获取用户ID
    let user_info_url = format!("{}/api/oauth/userinfo", oauth_config.auth_server_url);
    let user_response = match client
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

    if !user_response.status().is_success() {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "获取用户信息失败"
        }));
    }

    // 解析用户ID
    let user_info = match user_response.json::<serde_json::Value>().await {
        Ok(json) => json,
        Err(e) => {
            error!("解析用户信息失败: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "解析用户信息失败"
            }));
        }
    };

    let user_id = match user_info.get("id") {
        Some(id) => id.as_str().unwrap_or_default(),
        None => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "用户ID不存在"
            }));
        }
    };

    // 处理文件上传
    let mut avatar_data = None;
    
    while let Some(field) = payload.next().await {
        let field = match field {
            Ok(f) => f,
            Err(e) => {
                error!("获取表单字段失败: {}", e);
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "获取表单字段失败"
                }));
            }
        };
        
        let content_disposition = field.content_disposition();
        let field_name = content_disposition.get_name().unwrap_or_default();
        
        if field_name == "avatar" {
            // 读取文件数据
            let mut bytes = Vec::new();
            let mut field_stream = field;
            
            while let Some(chunk_result) = field_stream.next().await {
                match chunk_result {
                    Ok(chunk) => bytes.extend_from_slice(&chunk),
                    Err(e) => {
                        error!("读取文件块失败: {}", e);
                        return HttpResponse::BadRequest().json(serde_json::json!({
                            "error": "读取文件数据失败"
                        }));
                    }
                }
            }
            
            // 检查文件大小
            if bytes.len() > 4 * 1024 * 1024 {  // 4MB限制
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "文件过大，限制为4MB"
                }));
            }
            
            avatar_data = Some(bytes);
            break;
        }
    }

    // 如果没有上传文件
    let avatar_bytes = match avatar_data {
        Some(bytes) => bytes,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "没有找到头像文件"
            }));
        }
    };

    // 将文件发送到授权服务器
    let avatar_url = format!("{}/api/users/{}/avatar", oauth_config.auth_server_url, user_id);
    
    // 创建multipart表单
    let form = reqwest::multipart::Form::new()
        .part("avatar", reqwest::multipart::Part::bytes(avatar_bytes)
            .file_name("avatar.png")
            .mime_str("image/png").unwrap());
    
    // 发送请求
    let response = match client
        .post(&avatar_url)
        .header("Authorization", format!("Bearer {}", access_token))
        .multipart(form)
        .send()
        .await {
            Ok(resp) => resp,
            Err(e) => {
                error!("上传头像失败: {}", e);
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "上传头像失败"
                }));
            }
        };

    // 检查响应状态
    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_default();
        error!("上传头像失败，状态码: {}, 错误: {}", status, error_text);
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("上传头像失败: {}", error_text)
        }));
    }

    // 返回成功响应
    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "头像上传成功"
    }))
}

/// 获取用户信息API
#[get("/api/userinfo")]
pub async fn get_user_info_api(
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

/// 获取用户登录统计API
#[get("/api/user/login-stats")]
pub async fn get_login_stats_api(
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

    // 从userinfo接口获取用户ID
    let user_info_url = format!("{}/api/oauth/userinfo", oauth_config.auth_server_url);
    
    let user_response = match client
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

    if !user_response.status().is_success() {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "获取用户信息失败"
        }));
    }

    // 解析用户ID
    let user_info = match user_response.json::<serde_json::Value>().await {
        Ok(json) => json,
        Err(e) => {
            error!("解析用户信息失败: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "解析用户信息失败"
            }));
        }
    };

    let user_id = match user_info.get("id") {
        Some(id) => id.as_str().unwrap_or_default(),
        None => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "用户ID不存在"
            }));
        }
    };

    // 请求登录统计数据
    let stats_url = format!("{}/api/users/{}/login-stats", oauth_config.auth_server_url, user_id);
    
    let stats_response = match client
        .get(&stats_url)
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await {
            Ok(resp) => resp,
            Err(e) => {
                error!("请求登录统计失败: {}", e);
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "获取登录统计失败"
                }));
            }
        };

    if !stats_response.status().is_success() {
        let error_text = stats_response.text().await.unwrap_or_default();
        error!("获取登录统计响应错误: {}", error_text);
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "获取登录统计失败"
        }));
    }

    // 返回原始JSON响应
    match stats_response.text().await {
        Ok(text) => {
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

/// 个人资料页面路由
#[get("")]
pub async fn profile() -> impl Responder {
    // 直接返回静态HTML文件，不再使用模板渲染
    HttpResponse::Ok()
        .content_type("text/html")
        .body(include_str!("templates/profile.html"))
}

/// 登出路由
#[get("/logout")]
pub async fn logout() -> impl Responder {
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
        .append_header((http::header::LOCATION, "/auth"))
        .finish()
} 