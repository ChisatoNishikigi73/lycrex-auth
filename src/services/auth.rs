use chrono::{Duration, Utc};
use sqlx::{PgPool, query, query_as};
use uuid::Uuid;

use crate::errors::{AppError, AppResult};
use crate::models::{
    Authorization, AuthorizationRequest, Client, GrantType, Token, TokenRequest, User,
};
use crate::utils::{password, random, jwt};
use crate::config::Config;

pub async fn create_authorization(
    user_id: Uuid,
    auth_req: &AuthorizationRequest,
    db: &PgPool,
) -> AppResult<String> {
    // 验证客户端
    let client = find_client_by_client_id(&auth_req.client_id, db).await?;
    
    // 验证重定向URI
    if !client.redirect_uris.contains(&auth_req.redirect_uri) {
        return Err(AppError::ValidationError(
            "无效的重定向URI".to_string(),
        ));
    }
    
    // 获取全局配置
    let config = Config::get_global();
    
    // 创建授权码
    let code = random::generate_authorization_code();
    let now = Utc::now();
    
    // 使用配置中的授权码生命周期，单位为秒
    let expires_at = now + Duration::seconds(config.security.authorization_code_lifetime);
    
    // 存储授权记录
    query(
        r#"
        INSERT INTO authorizations (id, user_id, client_id, code, redirect_uri, scope, expires_at, created_at, used)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#)
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(client.id)
    .bind(&code)
    .bind(&auth_req.redirect_uri)
    .bind(auth_req.scope.as_deref())
    .bind(expires_at)
    .bind(now)
    .bind(false)
    .execute(db)
    .await
    .map_err(|e| AppError::DatabaseError(e))?;
    
    Ok(code)
}

pub async fn exchange_token(
    token_req: &TokenRequest,
    db: &PgPool,
) -> AppResult<Token> {
    // 验证客户端凭证
    let client = authenticate_client(&token_req.client_id, &token_req.client_secret, db).await?;
    
    // 根据授权类型处理
    let grant_type = GrantType::from(token_req.grant_type.as_str());
    
    match grant_type {
        GrantType::AuthorizationCode => {
            // 验证授权码
            let code = token_req.code.as_ref().ok_or_else(|| {
                AppError::ValidationError("授权码不能为空".to_string())
            })?;
            
            let redirect_uri = token_req.redirect_uri.as_ref().ok_or_else(|| {
                AppError::ValidationError("重定向URI不能为空".to_string())
            })?;
            
            // 查找并验证授权记录
            let auth = query_as::<_, Authorization>(
                r#"
                SELECT * FROM authorizations
                WHERE code = $1 AND client_id = $2 AND used = false AND expires_at > $3
                "#)
            .bind(code)
            .bind(client.id)
            .bind(Utc::now())
            .fetch_optional(db)
            .await
            .map_err(AppError::DatabaseError)?
            .ok_or_else(|| AppError::ValidationError("无效的授权码".to_string()))?;
            
            // 验证重定向URI
            if &auth.redirect_uri != redirect_uri {
                return Err(AppError::ValidationError(
                    "重定向URI不匹配".to_string(),
                ));
            }
            
            // 标记授权码为已使用
            query(r#"UPDATE authorizations SET used = true WHERE id = $1"#)
            .bind(auth.id)
            .execute(db)
            .await
            .map_err(AppError::DatabaseError)?;
            
            // 创建访问令牌
            create_token(auth.user_id, client.id, auth.scope, db).await
        }
        
        GrantType::RefreshToken => {
            // 处理刷新令牌
            let refresh_token = token_req.refresh_token.as_ref().ok_or_else(|| {
                AppError::ValidationError("刷新令牌不能为空".to_string())
            })?;
            
            let refresh_token_str = refresh_token.as_str();
            
            // 首先验证JWT格式的刷新令牌
            let token_data = jwt::verify_token(refresh_token_str)?;
            let user_id = token_data.claims.sub;
            
            // 查找原始令牌
            let original_token = query_as::<_, Token>(
                r#"
                SELECT * FROM tokens
                WHERE refresh_token = $1 AND client_id = $2 AND revoked = false
                "#)
            .bind(refresh_token_str)
            .bind(client.id)
            .fetch_optional(db)
            .await
            .map_err(AppError::DatabaseError)?
            .ok_or_else(|| AppError::ValidationError("无效的刷新令牌".to_string()))?;
            
            // 验证用户ID匹配
            if original_token.user_id != user_id {
                return Err(AppError::Unauthorized("令牌用户不匹配".to_string()));
            }
            
            if original_token.expires_at < Utc::now() {
                log::warn!("尝试使用过期的刷新令牌: {}", refresh_token_str);
                // 特别标记过期的令牌为撤销状态
                query(r#"UPDATE tokens SET revoked = true WHERE id = $1"#)
                    .bind(original_token.id)
                    .execute(db)
                    .await
                    .map_err(AppError::DatabaseError)?;
                return Err(AppError::Unauthorized("刷新令牌已过期".to_string()));
            }
            
            // 撤销原始令牌
            query(r#"UPDATE tokens SET revoked = true WHERE id = $1"#)
                .bind(original_token.id)
                .execute(db)
                .await
                .map_err(AppError::DatabaseError)?;
            
            log::info!("成功刷新令牌，用户ID: {}", user_id);
            
            // 创建新令牌
            create_token(original_token.user_id, client.id, original_token.scope, db).await
        }
        
        _ => Err(AppError::ValidationError(
            "不支持的授权类型".to_string(),
        )),
    }
}

async fn create_token(
    user_id: Uuid,
    client_id: Uuid,
    scope: Option<String>,
    db: &PgPool,
) -> AppResult<Token> {
    // 获取全局配置
    let config = Config::get_global();
    
    let now = Utc::now();
    
    // 使用配置中的访问令牌生命周期，单位为秒
    let expires_at = now + Duration::seconds(config.security.access_token_lifetime);
    
    // 获取客户端信息
    let client = query_as::<_, Client>(r#"SELECT * FROM clients WHERE id = $1"#)
    .bind(client_id)
    .fetch_one(db)
    .await
    .map_err(AppError::DatabaseError)?;
    
    // 生成JWT格式令牌，使用配置中的访问令牌生命周期
    let access_token = jwt::generate_token(
        user_id,
        &client.client_id,
        scope.clone(),
        Some(config.security.access_token_lifetime) // 使用配置的值
    )?;
    
    // 生成JWT格式的刷新令牌
    let refresh_token = Some(jwt::generate_refresh_token(
        user_id,
        &client.client_id,
        scope.clone()
    )?);
    
    // 存储令牌
    let token_id = Uuid::new_v4();
    let token = query_as::<_, Token>(
        r#"
        INSERT INTO tokens (id, access_token, refresh_token, token_type, expires_at, scope, user_id, client_id, created_at, updated_at, revoked)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING *
        "#)
    .bind(token_id)
    .bind(&access_token)
    .bind(refresh_token)
    .bind("Bearer")
    .bind(expires_at)
    .bind(scope.as_deref())
    .bind(user_id)
    .bind(client_id)
    .bind(now)
    .bind(now)
    .bind(false)
    .fetch_one(db)
    .await
    .map_err(AppError::DatabaseError)?;
    
    Ok(token)
}

pub async fn find_client_by_client_id(client_id: &str, db: &PgPool) -> AppResult<Client> {
    query_as::<_, Client>(r#"SELECT * FROM clients WHERE client_id = $1"#)
    .bind(client_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::DatabaseError)?
    .ok_or_else(|| AppError::NotFound("客户端未找到".to_string()))
}

pub async fn authenticate_client(
    client_id: &str,
    client_secret: &str,
    db: &PgPool,
) -> AppResult<Client> {
    let client = find_client_by_client_id(client_id, db).await?;
    
    if client.client_secret != client_secret {
        return Err(AppError::Unauthorized("客户端验证失败".to_string()));
    }
    
    Ok(client)
}

pub async fn get_user_info(user_id: Uuid, db: &PgPool) -> AppResult<User> {
    query_as::<_, User>(r#"SELECT * FROM users WHERE id = $1"#)
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::DatabaseError)?
    .ok_or_else(|| AppError::NotFound("用户未找到".to_string()))
}

pub async fn authenticate_user(
    email: &str,
    pass: &str,
    db: &PgPool,
) -> AppResult<User> {
    let user = query_as::<_, User>(r#"SELECT * FROM users WHERE email = $1"#)
    .bind(email)
    .fetch_optional(db)
    .await
    .map_err(AppError::DatabaseError)?
    .ok_or_else(|| AppError::AuthError("认证失败".to_string()))?;
    
    let password_valid = password::verify_password(pass, &user.password_hash)?;
    
    if !password_valid {
        return Err(AppError::AuthError("认证失败".to_string()));
    }
    
    Ok(user)
} 