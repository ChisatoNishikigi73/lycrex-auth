use serde::{Deserialize, Serialize};
use crate::models::User;
use crate::models::oauth::interface::OAuthResponse;

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

// 实现OAuthResponse接口
impl OAuthResponse for TestUserResponse {
    fn from_user(user: &User) -> Self {
        Self {
            id: user.id.to_string(),
            username: user.username.clone(),
            email: user.email.clone(),
            is_verified: user.email_verified,
            custom_field: "测试值".to_string(),
        }
    }
    
    fn get_id_str(&self) -> String {
        self.id.clone()
    }
}

// 保持向后兼容
impl From<User> for TestUserResponse {
    fn from(user: User) -> Self {
        Self::from_user(&user)
    }
} 