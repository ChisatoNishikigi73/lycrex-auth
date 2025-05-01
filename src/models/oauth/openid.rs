use serde::{Deserialize, Serialize};
use crate::models::User;
use crate::models::oauth::interface::OAuthResponse;

/// OpenID Connect标准用户响应结构体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenIdUserResponse {
    pub sub: String,
    pub name: String,
    pub preferred_username: String,
    pub email: String,
    pub email_verified: bool,
    pub picture: Option<String>,
}

// 实现OAuthResponse接口
impl OAuthResponse for OpenIdUserResponse {
    fn from_user(user: &User) -> Self {
        // 如果avatar存在，生成临时URL或直接使用base64数据
        let picture = user.avatar.clone().map(|avatar| {
            // 如果avatar已经是base64编码，直接返回
            // 实际使用时可以考虑生成临时URL
            format!("data:image/png;base64,{}", avatar)
        });
        
        Self {
            sub: user.id.to_string(),
            name: user.username.clone(),
            preferred_username: user.username.clone(),
            email: user.email.clone(),
            email_verified: user.email_verified,
            picture,
        }
    }
    
    fn get_id_str(&self) -> String {
        self.sub.clone()
    }
}

// 保持向后兼容，从User转换为OpenIdUserResponse
impl From<User> for OpenIdUserResponse {
    fn from(user: User) -> Self {
        Self::from_user(&user)
    }
} 