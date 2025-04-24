use actix_web::{HttpResponse, ResponseError};
use serde::Serialize;
use thiserror::Error;

/// 应用程序错误类型
#[derive(Error, Debug)]
pub enum AppError {
    /// 认证相关错误
    #[error("认证错误: {0}")]
    AuthError(String),
    
    /// 数据验证错误
    #[error("验证错误: {0}")]
    ValidationError(String),
    
    /// 数据库操作错误
    #[error("数据库错误: {0}")]
    DatabaseError(#[from] sqlx::Error),
    
    /// 内部服务器错误
    #[error("内部服务器错误: {0}")]
    InternalServerError(String),
    
    /// 请求参数错误
    #[error("请求错误: {0}")]
    #[allow(dead_code)]
    BadRequest(String),
    
    /// 资源未找到错误
    #[error("未找到: {0}")]
    NotFound(String),
    
    /// 未授权错误
    #[error("未授权: {0}")]
    Unauthorized(String),
    
    /// 禁止访问错误
    #[error("禁止访问: {0}")]
    #[allow(dead_code)]
    Forbidden(String),
}

/// API错误响应格式
#[derive(Serialize)]
struct ErrorResponse {
    /// HTTP状态码
    code: u16,
    /// 错误信息
    message: String,
}

impl ResponseError for AppError {
    /// 获取对应的HTTP状态码
    fn status_code(&self) -> actix_web::http::StatusCode {
        use actix_web::http::StatusCode;
        match self {
            AppError::AuthError(_) => StatusCode::UNAUTHORIZED,
            AppError::ValidationError(_) => StatusCode::BAD_REQUEST,
            AppError::DatabaseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::InternalServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,
        }
    }
    
    /// 生成HTTP错误响应
    fn error_response(&self) -> HttpResponse {
        let status_code = self.status_code();
        HttpResponse::build(status_code).json(ErrorResponse {
            code: status_code.as_u16(),
            message: self.to_string(),
        })
    }
}

/// 应用程序结果类型
pub type AppResult<T> = Result<T, AppError>; 