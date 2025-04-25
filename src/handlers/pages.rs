use actix_web::{web, HttpResponse, Responder};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct LoginQuery {
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub response_type: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
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