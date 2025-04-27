use actix_web::{web, HttpResponse, Responder};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct LoginQuery {
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub response_type: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub user_id: Option<String>,
    pub username: Option<String>,
}

// 登录页面
pub async fn login_page(
    query: web::Query<LoginQuery>,
    session: actix_session::Session,
) -> impl Responder {
    // 检查是否提供了client_id
    if query.client_id.is_none() || query.client_id.as_deref().unwrap_or("").is_empty() {
        log::warn!("访问登录页面但未提供client_id，显示警告页面");
        let warning = crate::utils::templates::render_warning("未提供有效的OAuth客户端参数，请通过正确的客户端应用访问本服务");
        return HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(warning);
    }
    
    // 检查当前会话
    let login_status = match session.get::<String>("user_id") {
        Ok(Some(user_id)) => {
            log::info!("用户已登录，用户ID: {}", user_id);
            format!("用户 {} 已登录", user_id)
        },
        _ => {
            log::info!("用户未登录，显示登录页面");
            "未登录".to_string()
        }
    };
    
    // 设置OAuth参数
    let client_id = query.client_id.as_deref().unwrap_or("");
    let redirect_uri = query.redirect_uri.as_deref().unwrap_or("");
    let response_type = query.response_type.as_deref().unwrap_or("");
    let scope = query.scope.as_deref().unwrap_or("");
    let state = query.state.as_deref().unwrap_or("");
    
    log::info!("显示登录页面，client_id: {}", client_id);
    
    // 使用模板渲染登录页面
    let html = crate::utils::templates::render_login(
        &login_status, 
        client_id, 
        redirect_uri, 
        response_type, 
        scope, 
        state
    );
    
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

// 注册页面
pub async fn register_page(query: web::Query<LoginQuery>) -> impl Responder {
    // 检查是否提供了client_id
    if query.client_id.is_none() || query.client_id.as_deref().unwrap_or("").is_empty() {
        log::warn!("访问注册页面但未提供client_id，显示警告页面");
        let warning = crate::utils::templates::render_warning("未提供有效的OAuth客户端参数，请通过正确的客户端应用访问本服务");
        return HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(warning);
    }
    
    // 直接使用注册页面模板
    log::info!("显示注册页面，client_id: {:?}", query.client_id);
    let html = crate::utils::templates::REGISTER_PAGE;
    
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

// 首页
pub async fn index_page(_session: actix_session::Session) -> impl Responder {
    // 显示API文档页面
    log::info!("访问首页，显示API文档");
    
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(crate::utils::templates::API_DOCS_PAGE)
}

// 欢迎页面
pub async fn welcome_page(
    query: web::Query<LoginQuery>,
    session: actix_session::Session,
) -> impl Responder {
    // 检查是否提供了client_id和redirect_uri
    if query.client_id.is_none() || query.redirect_uri.is_none() {
        log::warn!("访问欢迎页面但未提供必要参数，显示警告页面");
        let warning = crate::utils::templates::render_warning("未提供有效的OAuth客户端参数，请通过正确的客户端应用访问本服务");
        return HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(warning);
    }
    
    // 从会话或参数中获取用户信息
    let username = match session.get::<String>("user_id") {
        Ok(Some(user_id)) => {
            // 理想情况下，应该使用user_id查询数据库获取用户名
            // 这里简化处理，使用query参数中的用户名或默认值
            query.username.as_deref().unwrap_or("用户").to_string()
        },
        _ => {
            // 如果会话中没有，尝试从query中获取
            if let Some(user_id) = &query.user_id {
                query.username.as_deref().unwrap_or("用户").to_string()
            } else {
                // 没有用户ID，重定向到登录页面
                log::warn!("欢迎页面无法获取用户ID，重定向到登录页面");
                let redirect_url = format!(
                    "/login?client_id={}&redirect_uri={}&response_type={}&scope={}&state={}",
                    query.client_id.as_deref().unwrap_or(""),
                    query.redirect_uri.as_deref().unwrap_or(""),
                    query.response_type.as_deref().unwrap_or(""),
                    query.scope.as_deref().unwrap_or(""),
                    query.state.as_deref().unwrap_or("")
                );
                
                return HttpResponse::Found()
                    .append_header(("Location", redirect_url))
                    .finish();
            }
        }
    };
    
    // 构建回调URL
    let redirect_url = format!(
        "/api/oauth/authorize?client_id={}&redirect_uri={}&response_type={}&scope={}&state={}&user_id={}",
        query.client_id.as_deref().unwrap_or(""),
        query.redirect_uri.as_deref().unwrap_or(""),
        query.response_type.as_deref().unwrap_or(""),
        query.scope.as_deref().unwrap_or(""),
        query.state.as_deref().unwrap_or(""),
        query.user_id.as_deref().unwrap_or("")
    );
    
    log::info!("显示欢迎页面，回调URL: {}", redirect_url);
    
    // 渲染欢迎页面
    let html = crate::utils::templates::render_welcome(&username, &redirect_url);
    
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
} 