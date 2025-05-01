use chrono::Utc;
use sqlx::{PgPool, query, query_as, Row};
use uuid::Uuid;

use crate::errors::{AppError, AppResult};
use crate::models::{AdminUserResponse, User, UserCreate, OpenIdUserResponse};
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
        INSERT INTO users (id, username, email, password_hash, created_at, updated_at, email_verified, avatar)
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
    .bind(None::<String>) // 默认avatar为None
    .fetch_one(db)
    .await
    .map_err(AppError::DatabaseError)?;
    
    Ok(user)
}

pub async fn get_user_by_id(id: Uuid, db: &PgPool) -> AppResult<OpenIdUserResponse> {
    let user = query_as::<_, User>(r#"SELECT * FROM users WHERE id = $1"#)
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::DatabaseError)?
    .ok_or_else(|| AppError::NotFound("用户未找到".to_string()))?;
    
    Ok(OpenIdUserResponse::from(user))
}

/// 获取用户列表，支持分页和搜索
pub async fn admin_get_user_list(
    offset: i64,
    limit: i64,
    search: Option<&str>,
    db: &PgPool,
) -> AppResult<(Vec<AdminUserResponse>, i64)> {
    // 构建基本查询
    let mut count_query = String::from("SELECT COUNT(*) FROM users");
    let mut query_string = String::from("SELECT * FROM users");
    let mut params = Vec::new();
    
    // 添加搜索条件
    if let Some(search_term) = search {
        if !search_term.is_empty() {
            let search_condition = " WHERE username ILIKE $1 OR email ILIKE $1";
            count_query.push_str(search_condition);
            query_string.push_str(search_condition);
            params.push(format!("%{}%", search_term));
        }
    }
    
    // 添加排序和分页
    query_string.push_str(" ORDER BY created_at DESC LIMIT $");
    query_string.push_str(&(params.len() + 1).to_string());
    query_string.push_str(" OFFSET $");
    query_string.push_str(&(params.len() + 2).to_string());
    
    // 执行计数查询
    let total = if params.is_empty() {
        query("SELECT COUNT(*) FROM users")
            .fetch_one(db)
            .await?
            .get::<i64, _>(0)
    } else {
        let mut count_query = sqlx::query(&count_query);
        for param in &params {
            count_query = count_query.bind(param);
        }
        count_query
            .fetch_one(db)
            .await?
            .get::<i64, _>(0)
    };
    
    // 执行主查询
    let users = if params.is_empty() {
        query_as::<_, User>(&query_string)
            .bind(limit)
            .bind(offset)
            .fetch_all(db)
            .await?
    } else {
        let mut user_query = sqlx::query_as::<_, User>(&query_string);
        for param in &params {
            user_query = user_query.bind(param);
        }
        user_query
            .bind(limit)
            .bind(offset)
            .fetch_all(db)
            .await?
    };
    
    // 转换为UserResponse
    let user_responses = users.into_iter()
        .map(AdminUserResponse::from)
        .collect();
    
    Ok((user_responses, total))
}

pub async fn update_user(
    id: Uuid,
    username: Option<String>,
    email: Option<String>,
    avatar: Option<String>,
    db: &PgPool,
) -> AppResult<OpenIdUserResponse> {
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
    let avatar = avatar.or(user.avatar);
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
        SET username = $1, email = $2, updated_at = $3, avatar = $4
        WHERE id = $5
        RETURNING *
        "#)
    .bind(&username)
    .bind(&email)
    .bind(now)
    .bind(&avatar)
    .bind(id)
    .fetch_one(db)
    .await
    .map_err(AppError::DatabaseError)?;
    
    Ok(OpenIdUserResponse::from(updated_user))
}

#[allow(dead_code)]
pub async fn update_user_email_verified(
    id: Uuid,
    email_verified: bool,
    db: &PgPool,
) -> AppResult<OpenIdUserResponse> {
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
    
    Ok(OpenIdUserResponse::from(updated_user))
}

/// 删除用户
pub async fn delete_user(id: Uuid, db: &PgPool) -> AppResult<()> {
    // 验证用户存在
    let user_exists = query("SELECT 1 FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(AppError::DatabaseError)?
        .is_some();
    
    if !user_exists {
        return Err(AppError::NotFound("用户不存在".to_string()));
    }
    
    // 删除用户相关的所有数据（先删除外键关联表）
    
    // 删除令牌
    query("DELETE FROM tokens WHERE user_id = $1")
        .bind(id)
        .execute(db)
        .await
        .map_err(AppError::DatabaseError)?;
    
    // 删除授权码
    query("DELETE FROM authorizations WHERE user_id = $1")
        .bind(id)
        .execute(db)
        .await
        .map_err(AppError::DatabaseError)?;
    
    // 删除用户创建的客户端应用
    query("DELETE FROM clients WHERE user_id = $1")
        .bind(id)
        .execute(db)
        .await
        .map_err(AppError::DatabaseError)?;
    
    // 最后删除用户
    let result = query("DELETE FROM users WHERE id = $1")
        .bind(id)
        .execute(db)
        .await
        .map_err(AppError::DatabaseError)?;
    
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("用户不存在".to_string()));
    }
    
    Ok(())
}

/// 获取用户最近30天的登录次数
pub async fn get_recent_login_count(user_id: Uuid, db: &PgPool) -> AppResult<i64> {
    let fourteen_days_ago = Utc::now() - chrono::Duration::days(30);
    
    let count = query(
        r#"
        SELECT COUNT(*) 
        FROM tokens 
        WHERE user_id = $1 
        AND created_at >= $2
        "#)
    .bind(user_id)
    .bind(fourteen_days_ago)
    .fetch_one(db)
    .await
    .map_err(AppError::DatabaseError)?
    .get::<i64, _>(0);
    
    Ok(count)
} 