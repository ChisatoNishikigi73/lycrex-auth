use serde::{Deserialize, Serialize};
use crate::models::User;
use crate::models::oauth::interface::OAuthResponse;

/// Lycrex 用户响应结构体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LycrexUserResponse {
    // 标准OAuth字段
    pub sub: String,
    pub name: String,
    pub preferred_username: String,
    pub email: String,
    pub email_verified: bool,
    
    // Lycrex特殊字段
    pub id: String,
    pub avatar: Option<String>,
    pub lycrex_id: String,
    pub permissions: Vec<String>,
    pub created_at: String,
    pub last_login: Option<String>,
    pub recent_login_count: i64, // 最近14天的登录次数
}

// 实现OAuthResponse接口
impl OAuthResponse for LycrexUserResponse {
    fn from_user(user: &User) -> Self {
        let id_str = user.id.to_string();
        Self {
            sub: id_str.clone(),
            name: user.username.clone(),
            preferred_username: user.username.clone(),
            email: user.email.clone(),
            email_verified: user.email_verified,
            
            // Lycrex特有字段
            id: id_str.clone(),
            avatar: user.avatar_url.clone(),
            lycrex_id: id_str,
            permissions: vec!["user".to_string()],
            created_at: user.created_at.to_rfc3339(),
            last_login: Some(user.created_at.to_rfc3339()),
            recent_login_count: 0, // 在post_process中会被更新
        }
    }
    
    fn get_id_str(&self) -> String {
        self.id.clone()
    }
    
    // 实现后处理方法，获取最近登录次数
    async fn post_process(mut self, user_id: &uuid::Uuid, db: &sqlx::PgPool) -> Result<Self, String> {
        // 获取最近登录次数
        match crate::services::user::get_recent_login_count(*user_id, db).await {
            Ok(count) => {
                self.recent_login_count = count;
                Ok(self)
            },
            Err(e) => {
                // 如果获取失败，记录错误但不阻止返回（只是count保持为0）
                log::warn!("获取用户 {} 最近登录次数失败: {}", user_id, e);
                Ok(self)
            }
        }
    }
}

/// 转换为Lycrex兼容的响应 (保持向后兼容)
impl From<User> for LycrexUserResponse {
    fn from(user: User) -> Self {
        Self::from_user(&user)
    }
}

/// Lycrex的授权请求结构
#[derive(Debug, Serialize, Deserialize)]
pub struct LycrexAuthRequest {
    pub client_id: String,
    pub client_secret: String,
    pub response_type: String,
    pub scope: Option<String>,
    pub redirect_uri: String,
    pub state: Option<String>,
} 