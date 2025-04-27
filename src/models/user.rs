use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, FromRow, Clone)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub email_verified: bool,
    pub avatar_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserCreate {
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserLogin {
    pub email: String,
    pub password: String,
}

/// OpenID Connect标准用户响应结构体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenIdUserResponse {
    pub sub: String,
    pub name: String,
    pub preferred_username: String,
    pub email: String,
    pub email_verified: bool,
}

/// Gitea兼容用户响应结构体 (扩展自OpenID标准)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GiteaUserResponse {
    // OpenID Connect标准字段
    pub sub: String,
    pub name: String,
    pub preferred_username: String,
    pub email: String,
    pub email_verified: bool,
    
    // Gitea兼容字段
    pub id: String, // 将在处理时转换为数字
    pub login: String,
    pub username: String,
    pub avatar_url: Option<String>,
}

/// 测试用户响应结构体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestUserResponse {
    // 与测试客户端UserInfo兼容的字段
    pub id: String,
    pub username: String,
    pub email: String,
    // 额外的测试字段
    pub is_verified: bool,
    pub custom_field: String,
}

/// 管理员用户查询响应，包含更多管理所需信息
#[derive(Debug, Serialize, Deserialize)]
pub struct AdminUserResponse {
    // OpenID Connect标准字段
    pub sub: String,
    pub name: String,
    pub preferred_username: String,
    pub email: String,
    pub email_verified: bool,
    
    // Gitea兼容字段
    pub id: String,
    pub login: String,
    pub username: String,
    pub avatar_url: Option<String>,
    
    // 管理员额外需要的字段
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}

// 从User转换为OpenIdUserResponse
impl From<User> for OpenIdUserResponse {
    fn from(user: User) -> Self {
        Self {
            sub: user.id.to_string(),
            name: user.username.clone(),
            preferred_username: user.username.clone(),
            email: user.email.clone(),
            email_verified: user.email_verified,
        }
    }
}

// 从User转换为GiteaUserResponse
impl From<User> for GiteaUserResponse {
    fn from(user: User) -> Self {
        let id_str = user.id.to_string();
        
        Self {
            sub: id_str.clone(),
            name: user.username.clone(),
            preferred_username: user.username.clone(),
            email: user.email.clone(),
            email_verified: user.email_verified,
            
            // Gitea兼容字段
            id: id_str,
            login: user.username.clone(),
            username: user.username,
            avatar_url: user.avatar_url,
        }
    }
}

// 从User转换为TestUserResponse
impl From<User> for TestUserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id.to_string(),
            username: user.username,
            email: user.email,
            is_verified: user.email_verified,
            custom_field: "测试值".to_string(),
        }
    }
}

impl From<User> for AdminUserResponse {
    fn from(user: User) -> Self {
        Self {
            sub: user.id.to_string(),
            name: user.username.clone(),
            preferred_username: user.username.clone(),
            email: user.email,
            email_verified: user.email_verified,
            id: user.id.to_string(),
            login: user.username.clone(),
            username: user.username,
            avatar_url: user.avatar_url,
            created_at: Some(user.created_at),
        }
    }
} 