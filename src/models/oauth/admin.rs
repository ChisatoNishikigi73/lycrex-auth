use chrono;
use serde::{Deserialize, Serialize};
use crate::models::User;
use crate::models::oauth::interface::OAuthResponse;

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

// 实现OAuthResponse接口
impl OAuthResponse for AdminUserResponse {
    fn from_user(user: &User) -> Self {
        Self {
            sub: user.id.to_string(),
            name: user.username.clone(),
            preferred_username: user.username.clone(),
            email: user.email.clone(),
            email_verified: user.email_verified,
            id: user.id.to_string(),
            login: user.username.clone(),
            username: user.username.clone(),
            avatar_url: user.avatar_url.clone(),
            created_at: Some(user.created_at),
        }
    }
    
    fn get_id_str(&self) -> String {
        self.id.clone()
    }
}

// 保持向后兼容
impl From<User> for AdminUserResponse {
    fn from(user: User) -> Self {
        Self::from_user(&user)
    }
} 