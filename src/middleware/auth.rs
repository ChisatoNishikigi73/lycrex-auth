use std::future::{ready, Ready};
use std::pin::Pin;

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage,
};
use futures::Future;
use jsonwebtoken::TokenData;
use uuid::Uuid;

use crate::errors::AppError;
use crate::utils::jwt;
use crate::models::TokenClaims;

// 常量定义
const AUTH_HEADER: &str = "Authorization";
const BEARER_PREFIX: &str = "Bearer ";

// 错误消息常量
const ERR_NO_TOKEN: &str = "未提供认证令牌";
const ERR_INVALID_HEADER: &str = "无效的认证头";
const ERR_INVALID_FORMAT: &str = "无效的认证令牌格式";

// 定义认证中间件
pub struct Auth;

// 当前用户提取器
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: Uuid,
}

// 实现中间件工厂
impl<S, B> Transform<S, ServiceRequest> for Auth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddleware { service }))
    }
}

// 实际的中间件服务
pub struct AuthMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for AuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        log_request_info(&req);
        
        // 从请求头中获取并验证token
        let token_result = extract_and_validate_token(&req);
        
        match token_result {
            Ok(token_data) => {
                // 将用户ID添加到请求扩展中
                req.extensions_mut().insert(AuthenticatedUser {
                    user_id: token_data.claims.sub,
                });
                
                // 继续处理请求
                let fut = self.service.call(req);
                Box::pin(async move {
                    let res = fut.await?;
                    Ok(res)
                })
            },
            Err(err) => Box::pin(async { Err(err.into()) }),
        }
    }
}

// 辅助函数：记录请求信息
fn log_request_info(req: &ServiceRequest) {
    let headers = req.headers();
    let mut headers_str = String::new();
    
    for (key, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            headers_str.push_str(&format!("{}: {}, ", key, v));
        }
    }
    
    log::info!(
        "认证中间件 | 路径: {} | 方法: {} | 请求头: {}", 
        req.path(), 
        req.method(), 
        headers_str
    );
}

// 辅助函数：提取和验证token
fn extract_and_validate_token(req: &ServiceRequest) -> Result<TokenData<TokenClaims>, AppError> {
    // 获取认证头
    let auth_header = req.headers()
        .get(AUTH_HEADER)
        .ok_or_else(|| {
            log::error!("认证失败 | 原因: {} | 路径: {}", ERR_NO_TOKEN, req.path());
            AppError::Unauthorized(ERR_NO_TOKEN.to_string())
        })?;
    
    // 转换认证头为字符串
    let auth_str = auth_header.to_str().map_err(|e| {
        log::error!("认证失败 | 原因: {} | 详情: {}", ERR_INVALID_HEADER, e);
        AppError::Unauthorized(ERR_INVALID_HEADER.to_string())
    })?;
    
    // 验证Bearer前缀
    if !auth_str.starts_with(BEARER_PREFIX) {
        log::error!("认证失败 | 原因: {} | 收到: {}", ERR_INVALID_FORMAT, auth_str);
        return Err(AppError::Unauthorized(ERR_INVALID_FORMAT.to_string()));
    }
    
    // 提取token
    let token = &auth_str[BEARER_PREFIX.len()..];
    log::info!("处理Token验证 | 路径: {} | 令牌: {}", req.path(), token);
    
    // 验证JWT令牌
    jwt::verify_token(token).map_err(|e| {
        log::error!("认证失败 | 原因: 无效的令牌 | 详情: {}", e);
        AppError::Unauthorized(format!("无效的认证令牌: {}", e))
    })
} 