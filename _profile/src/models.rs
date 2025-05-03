use serde::{Deserialize, Serialize};

/// 用户信息结构体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "preferred_username")]
    pub username: String,
    #[serde(rename = "email")]
    pub email: String,
    #[serde(rename = "email_verified")]
    pub email_verified: bool,
    #[serde(rename = "avatar_url", default)]
    pub avatar_url: Option<String>,
    #[serde(rename = "avatar", default)]
    pub avatar: Option<String>,
    #[serde(rename = "picture", default)]
    pub picture: Option<String>,
    #[serde(rename = "created_at")]
    pub created_at: String,
    #[serde(rename = "last_login_at", default)]
    pub last_login_at: Option<String>,
    #[serde(rename = "is_active", default = "default_is_active")]
    pub is_active: bool,
    #[serde(rename = "recent_login_count", default)]
    pub recent_login_count: Option<i64>,
}

/// 默认激活状态
pub fn default_is_active() -> bool {
    true
}

/// OAuth令牌响应
#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[allow(dead_code)]
    pub token_type: String,
    pub expires_in: i64,
    #[serde(default)]
    #[allow(dead_code)]
    pub refresh_token: Option<String>,
}

/// 已处理的授权码集合
pub struct ProcessedCodes {
    pub codes: std::collections::HashSet<String>
} 