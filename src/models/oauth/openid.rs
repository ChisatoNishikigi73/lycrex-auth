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
}

// 实现OAuthResponse接口
impl OAuthResponse for OpenIdUserResponse {
    fn from_user(user: &User) -> Self {
        Self {
            sub: user.id.to_string(),
            name: user.username.clone(),
            preferred_username: user.username.clone(),
            email: user.email.clone(),
            email_verified: user.email_verified,
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