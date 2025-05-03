use serde::{Deserialize, Serialize};
use crate::models::User;
use crate::models::oauth::interface::OAuthResponse;
use crate::utils::id::uuid_to_gitea_id;

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
    pub id: i64, // 修改为整数类型以匹配Gitea的期望
    pub login: String,
    pub username: String,
    pub avatar_url: String, // 修改为非Option类型，确保始终有值
}

// 实现OAuthResponse接口
impl OAuthResponse for GiteaUserResponse {
    fn from_user(user: &User) -> Self {
        let id_str = user.id.to_string();
        
        // 使用Gitea专用的ID转换函数，生成较小且稳定的ID
        let id_num = uuid_to_gitea_id(user.id);
        
        // 直接使用base64格式的头像数据，而不是URL
        // Gitea需要直接使用头像数据而不是URL引用
        let avatar_url = match &user.avatar {
            Some(avatar_base64) => {
                // 确保头像数据有data:前缀
                if avatar_base64.starts_with("data:") {
                    avatar_base64.clone()
                } else {
                    format!("data:image/png;base64,{}", avatar_base64)
                }
            },
            None => {
                "".to_string()
            }
        };
        
        Self {
            sub: id_str.clone(),
            name: user.username.clone(),
            preferred_username: user.username.clone(),
            email: user.email.clone(),
            email_verified: user.email_verified,
            
            // Gitea兼容字段
            id: id_num,
            login: user.username.clone(),
            username: user.username.clone(),
            avatar_url,
        }
    }
    
    fn get_id_str(&self) -> String {
        self.id.to_string()
    }
}

// 保持向后兼容
impl From<User> for GiteaUserResponse {
    fn from(user: User) -> Self {
        Self::from_user(&user)
    }
} 