use serde::{Deserialize, Serialize};
use crate::models::User;
use crate::models::oauth::interface::OAuthResponse;
use crate::routes::service::get_avatar_url_by_id;
use crate::utils::id::uuid_to_gitea_id;

/// Gitea兼容用户响应结构体 (符合Gitea API标准)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GiteaUserResponse {
    // Gitea标准字段
    pub id: i64,
    pub login: String,
    pub full_name: String,
    pub email: String,
    pub avatar_url: String,
    pub html_url: String,
    pub is_admin: bool,
    pub username: String,
    
    // OpenID Connect标准字段（保留向后兼容性）
    pub sub: String,
    pub name: String,
    pub preferred_username: String,
    pub email_verified: bool,
}

// 实现OAuthResponse接口
impl OAuthResponse for GiteaUserResponse {
    fn from_user(user: &User) -> Self {
        let id_str = user.id.to_string();
        
        // 使用更可靠的UUID转换工具生成稳定的i64 ID
        let id_num = uuid_to_gitea_id(user.id);
        
        // 从用户的avatar字段生成avatar_url，确保URL是绝对路径
        let avatar_url = get_avatar_url_by_id(user.id);
        
        // 构建个人主页URL
        let html_url = format!("https://lycrex.com");
        
        Self {
            // Gitea标准字段
            id: id_num,
            login: user.username.clone(),
            full_name: user.username.clone(), // 如果没有专门的全名字段，可以初始设置为用户名
            email: user.email.clone(),
            avatar_url,
            html_url,
            is_admin: false, // 默认非管理员
            username: user.username.clone(),
            
            // OpenID Connect标准字段
            sub: id_str,
            name: user.username.clone(),
            preferred_username: user.username.clone(),
            email_verified: user.email_verified,
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