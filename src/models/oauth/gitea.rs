use serde::{Deserialize, Serialize};
use crate::models::User;
use crate::models::oauth::interface::OAuthResponse;

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

// 实现OAuthResponse接口
impl OAuthResponse for GiteaUserResponse {
    fn from_user(user: &User) -> Self {
        let id_str = user.id.to_string();
        
        // 从用户的avatar字段生成avatar_url
        let avatar_url = user.avatar.clone().map(|avatar| {
            // 如果需要生成URL，可以在此处理
            // 目前直接返回base64格式
            format!("data:image/png;base64,{}", avatar)
        });
        
        Self {
            sub: id_str.clone(),
            name: user.username.clone(),
            preferred_username: user.username.clone(),
            email: user.email.clone(),
            email_verified: user.email_verified,
            
            // Gitea兼容字段
            id: id_str,
            login: user.username.clone(),
            username: user.username.clone(),
            avatar_url,
        }
    }
    
    fn get_id_str(&self) -> String {
        self.id.clone()
    }
}

// 保持向后兼容
impl From<User> for GiteaUserResponse {
    fn from(user: User) -> Self {
        Self::from_user(&user)
    }
} 