use chrono::{Duration, Utc};
use sqlx::{PgPool, query, query_as, Row};
use uuid::Uuid;

use crate::errors::{AppError, AppResult};
use crate::models::Token;
use crate::utils::jwt;
use crate::config::Config;

#[allow(dead_code)]
pub async fn create_access_token(
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
    
    // 生成JWT格式令牌
    let client_id_str = client_id.to_string();
    let access_token = jwt::generate_token(
        user_id,
        &client_id_str,
        scope.clone(),
        Some(config.security.access_token_lifetime) // 使用配置的值
    )?;
    
    // 生成JWT格式的刷新令牌
    let refresh_token = Some(jwt::generate_refresh_token(
        user_id,
        &client_id_str,
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

#[allow(dead_code)]
pub async fn revoke_token(token_id: &str, db: &PgPool) -> AppResult<()> {
    // 查找令牌
    let token = query(
        r#"SELECT id FROM tokens WHERE access_token = $1 OR refresh_token = $1"#)
    .bind(token_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::DatabaseError)?;
    
    if let Some(row) = token {
        // 撤销令牌
        let token_id: Uuid = row.get("id");
        query(r#"UPDATE tokens SET revoked = true WHERE id = $1"#)
        .bind(token_id)
        .execute(db)
        .await
        .map_err(AppError::DatabaseError)?;
        
        Ok(())
    } else {
        Err(AppError::NotFound("令牌未找到".to_string()))
    }
}

#[allow(dead_code)]
pub async fn validate_token(token: &str, _db: &PgPool) -> AppResult<Uuid> {
    // 只验证JWT格式，不查询数据库
    let token_data = jwt::verify_token(token)?;
    
    // 返回用户ID
    Ok(token_data.claims.sub)
}

// 检查令牌是否被撤销（可选，在高安全性场景使用）
#[allow(dead_code)]
pub async fn check_token_revoked(token: &str, db: &PgPool) -> AppResult<bool> {
    let result = query(
        r#"SELECT revoked FROM tokens WHERE access_token = $1"#)
    .bind(token)
    .fetch_optional(db)
    .await
    .map_err(AppError::DatabaseError)?;
    
    if let Some(row) = result {
        let revoked: bool = row.get("revoked");
        Ok(revoked)
    } else {
        // 如果令牌不在数据库中，假设它是无效的
        Ok(true)
    }
}

#[allow(dead_code)]
pub async fn clean_expired_tokens(db: &PgPool) -> AppResult<u64> {
    let now = Utc::now();
    
    // 删除过期令牌
    let result = query(r#"DELETE FROM tokens WHERE expires_at < $1"#)
    .bind(now)
    .execute(db)
    .await
    .map_err(AppError::DatabaseError)?;
    
    Ok(result.rows_affected())
} 