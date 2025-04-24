use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Token {
    pub id: Uuid,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub expires_at: DateTime<Utc>,
    pub scope: Option<String>,
    pub user_id: Uuid,
    pub client_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub revoked: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: Uuid,     // 用户ID
    pub aud: String,   // 客户端ID
    pub exp: i64,      // 过期时间
    pub iat: i64,      // 签发时间
    pub scope: Option<String>, // 权限范围
}

impl Token {
    pub fn to_response(&self, now: DateTime<Utc>) -> TokenResponse {
        let expires_in = (self.expires_at - now).num_seconds();
        
        TokenResponse {
            access_token: self.access_token.clone(),
            token_type: self.token_type.clone(),
            expires_in,
            refresh_token: self.refresh_token.clone(),
            scope: self.scope.clone(),
        }
    }
} 