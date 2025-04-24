use std::future::{ready, Ready};
use std::pin::Pin;

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage,
};
use futures::Future;
use uuid::Uuid;

use crate::errors::AppError;
use crate::utils::jwt;

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
        // 从请求头中获取authorization
        let auth_header = req.headers().get("Authorization");
        
        if auth_header.is_none() {
            log::error!("未提供认证令牌，路径：{}", req.path());
            let err = AppError::Unauthorized("未提供认证令牌".to_string());
            return Box::pin(async { Err(err.into()) });
        }
        
        let auth_header = match auth_header.unwrap().to_str() {
            Ok(header) => header,
            Err(e) => {
                log::error!("无法读取认证头: {}", e);
                let err = AppError::Unauthorized("无效的认证头".to_string());
                return Box::pin(async { Err(err.into()) });
            }
        };
        
        // 验证Bearer令牌
        if !auth_header.starts_with("Bearer ") {
            log::error!("无效的认证令牌格式: {}", auth_header);
            let err = AppError::Unauthorized("无效的认证令牌格式".to_string());
            return Box::pin(async { Err(err.into()) });
        }
        
        let token = auth_header[7..].to_string();
        log::info!("处理Token验证请求: {}", req.path());
        
        // 只验证JWT令牌，不查询数据库
        let token_data = match jwt::verify_token(&token) {
            Ok(data) => {
                log::info!("令牌验证成功，用户ID: {}", data.claims.sub);
                data
            },
            Err(e) => {
                log::error!("无效的认证令牌: {}", e);
                let err = AppError::Unauthorized(format!("无效的认证令牌: {}", e));
                return Box::pin(async { Err(err.into()) });
            }
        };
        
        // 将用户ID添加到请求扩展中
        req.extensions_mut().insert(AuthenticatedUser {
            user_id: token_data.claims.sub,
        });
        
        let fut = self.service.call(req);
        
        Box::pin(async move {
            let res = fut.await?;
            Ok(res)
        })
    }
} 