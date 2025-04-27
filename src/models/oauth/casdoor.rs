use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Casdoor OAuth用户响应结构体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CasdoorUserResponse {
    // 标准OAuth字段
    pub sub: String,
    pub name: String,
    pub preferred_username: String,
    pub email: String,
    pub email_verified: bool,
    
    // Casdoor特殊字段
    pub id: String,
    pub owner: Option<String>,
    pub avatar: Option<String>,
    pub phone: Option<String>,
    pub address: Option<String>,
    pub affiliation: Option<String>,
    pub tag: Option<String>,
    pub score: Option<i32>,
    pub is_admin: Option<bool>,
    pub is_global_admin: Option<bool>,
    pub is_forbidden: Option<bool>,
    pub signin_provider: Option<String>,
}

/// 从我们的用户模型转换为Casdoor兼容的响应
impl From<crate::models::User> for CasdoorUserResponse {
    fn from(user: crate::models::User) -> Self {
        let id_str = user.id.to_string();
        
        Self {
            sub: id_str.clone(),
            name: user.username.clone(),
            preferred_username: user.username.clone(),
            email: user.email.clone(),
            email_verified: user.email_verified,
            
            // Casdoor特有字段的默认值
            id: id_str,
            owner: Some("lycrex".to_string()),
            avatar: user.avatar_url,
            phone: None,
            address: None,
            affiliation: None,
            tag: None,
            score: None,
            is_admin: None,
            is_global_admin: None,
            is_forbidden: None,
            signin_provider: Some("lycrex".to_string()),
        }
    }
}

/// Casdoor的OAuth请求结构
#[derive(Debug, Serialize, Deserialize)]
pub struct CasdoorAuthRequest {
    pub client_id: String,
    pub client_secret: String,
    pub grant_type: String,
    pub scope: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub state: Option<String>,
}

/// Casdoor的OAuth令牌响应
#[derive(Debug, Serialize, Deserialize)]
pub struct CasdoorTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub refresh_token: Option<String>,
    pub expires_in: i64,
    pub scope: Option<String>,
    pub id_token: Option<String>,
} 