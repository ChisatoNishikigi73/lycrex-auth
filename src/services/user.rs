use chrono::Utc;
use sqlx::{PgPool, query, query_as};
use uuid::Uuid;

use crate::errors::{AppError, AppResult};
use crate::models::{User, UserCreate, UserResponse};
use crate::utils::password;

// 查找用户ID是否存在
pub async fn find_user_by_id(id: Uuid, db: &PgPool) -> AppResult<Option<User>> {
    let user = query_as::<_, User>(r#"SELECT * FROM users WHERE id = $1"#)
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::DatabaseError)?;
    
    Ok(user)
}

pub async fn create_user(user: &UserCreate, db: &PgPool) -> AppResult<User> {
    // 检查邮箱是否已存在
    let existing_user = query(r#"SELECT id FROM users WHERE email = $1"#)
    .bind(&user.email)
    .fetch_optional(db)
    .await
    .map_err(AppError::DatabaseError)?;
    
    if existing_user.is_some() {
        return Err(AppError::ValidationError("邮箱已被注册".to_string()));
    }
    
    // 哈希密码
    let password_hash = password::hash_password(&user.password)?;
    
    // 创建用户
    let now = Utc::now();
    let user_id = Uuid::new_v4();
    
    let user = query_as::<_, User>(
        r#"
        INSERT INTO users (id, username, email, password_hash, created_at, updated_at, email_verified, avatar_url)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING *
        "#)
    .bind(user_id)
    .bind(&user.username)
    .bind(&user.email)
    .bind(&password_hash)
    .bind(now)
    .bind(now)
    .bind(false) // 默认email_verified为false
    .bind(None::<String>) // 默认avatar_url为None
    .fetch_one(db)
    .await
    .map_err(AppError::DatabaseError)?;
    
    Ok(user)
}

pub async fn get_user_by_id(id: Uuid, db: &PgPool) -> AppResult<UserResponse> {
    let user = query_as::<_, User>(r#"SELECT * FROM users WHERE id = $1"#)
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::DatabaseError)?
    .ok_or_else(|| AppError::NotFound("用户未找到".to_string()))?;
    
    Ok(UserResponse::from(user))
}

pub async fn update_user(
    id: Uuid,
    username: Option<String>,
    email: Option<String>,
    avatar_url: Option<String>,
    db: &PgPool,
) -> AppResult<UserResponse> {
    // 检查用户是否存在
    let user = query_as::<_, User>(r#"SELECT * FROM users WHERE id = $1"#)
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::DatabaseError)?
    .ok_or_else(|| AppError::NotFound("用户未找到".to_string()))?;
    
    // 更新字段
    let username = username.unwrap_or_else(|| user.username.clone());
    let email = email.unwrap_or_else(|| user.email.clone());
    let avatar_url = avatar_url.or(user.avatar_url);
    let now = Utc::now();
    
    // 如果邮箱被修改，检查是否已被使用
    if email != user.email {
        let existing_user = query(r#"SELECT id FROM users WHERE email = $1 AND id != $2"#)
        .bind(&email)
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(AppError::DatabaseError)?;
        
        if existing_user.is_some() {
            return Err(AppError::ValidationError("邮箱已被注册".to_string()));
        }
    }
    
    // 更新用户
    let updated_user = query_as::<_, User>(
        r#"
        UPDATE users
        SET username = $1, email = $2, updated_at = $3, avatar_url = $4
        WHERE id = $5
        RETURNING *
        "#)
    .bind(&username)
    .bind(&email)
    .bind(now)
    .bind(&avatar_url)
    .bind(id)
    .fetch_one(db)
    .await
    .map_err(AppError::DatabaseError)?;
    
    Ok(UserResponse::from(updated_user))
}

#[allow(dead_code)]
pub async fn update_user_email_verified(
    id: Uuid,
    email_verified: bool,
    db: &PgPool,
) -> AppResult<UserResponse> {
    // 检查用户是否存在
    let _ = query_as::<_, User>(r#"SELECT * FROM users WHERE id = $1"#)
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::DatabaseError)?
    .ok_or_else(|| AppError::NotFound("用户未找到".to_string()))?;
    
    // 更新邮箱验证状态
    let now = Utc::now();
    
    let updated_user = query_as::<_, User>(
        r#"
        UPDATE users
        SET email_verified = $1, updated_at = $2
        WHERE id = $3
        RETURNING *
        "#)
    .bind(email_verified)
    .bind(now)
    .bind(id)
    .fetch_one(db)
    .await
    .map_err(AppError::DatabaseError)?;
    
    Ok(UserResponse::from(updated_user))
} 