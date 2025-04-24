use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use uuid::Uuid;

use crate::config::Config;
use crate::errors::AppError;
use crate::models::TokenClaims;

/// 生成JWT访问令牌
///
/// # 参数
/// * `user_id` - 用户ID
/// * `client_id` - 客户端应用ID
/// * `scope` - 令牌授权范围
/// * `expires_in` - 令牌有效期（秒），如果为None则使用配置中的默认值
///
/// # 返回
/// * `Result<String, AppError>` - 成功返回JWT令牌字符串，失败返回错误
pub fn generate_token(
    user_id: Uuid,
    client_id: &str,
    scope: Option<String>,
    expires_in: Option<i64>,
) -> Result<String, AppError> {
    let config = Config::get_global();
    let now = Utc::now();
    
    // 使用配置中的默认值或指定的过期时间
    let token_lifetime = expires_in.unwrap_or(config.security.access_token_lifetime);
    let expires_at = now + Duration::seconds(token_lifetime);
    
    let claims = TokenClaims {
        sub: user_id,
        aud: client_id.to_string(),
        exp: expires_at.timestamp(),
        iat: now.timestamp(),
        scope,
    };
    
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.server.secret_key.as_bytes()),
    )
    .map_err(|e| AppError::InternalServerError(format!("无法生成令牌: {}", e)))
}

/// 生成JWT刷新令牌，用于获取新的访问令牌
///
/// # 参数
/// * `user_id` - 用户ID
/// * `client_id` - 客户端应用ID
/// * `scope` - 令牌授权范围
///
/// # 返回
/// * `Result<String, AppError>` - 成功返回JWT刷新令牌字符串，失败返回错误
pub fn generate_refresh_token(
    user_id: Uuid,
    client_id: &str,
    scope: Option<String>,
) -> Result<String, AppError> {
    let config = Config::get_global();
    let now = Utc::now();
    
    // 使用配置中的刷新令牌生命周期（天）
    let refresh_lifetime_days = config.security.refresh_token_lifetime;
    let expires_at = now + Duration::days(refresh_lifetime_days);
    
    let claims = TokenClaims {
        sub: user_id,
        aud: client_id.to_string(),
        exp: expires_at.timestamp(),
        iat: now.timestamp(),
        scope,
    };
    
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.server.secret_key.as_bytes()),
    )
    .map_err(|e| AppError::InternalServerError(format!("无法生成刷新令牌: {}", e)))
}

/// 验证JWT令牌并解析其中的声明信息
///
/// # 参数
/// * `token` - JWT令牌字符串
///
/// # 返回
/// * `Result<TokenData<TokenClaims>, AppError>` - 成功返回令牌数据与声明，失败返回错误
pub fn verify_token(token: &str) -> Result<TokenData<TokenClaims>, AppError> {
    let config = Config::get_global();
    
    // 创建自定义验证，禁用audience验证
    let mut validation = Validation::default();
    validation.validate_aud = false; // 禁用audience验证
    
    decode::<TokenClaims>(
        token,
        &DecodingKey::from_secret(config.server.secret_key.as_bytes()),
        &validation,
    )
    .map_err(|e| AppError::AuthError(format!("无效的令牌: {}", e)))
} 