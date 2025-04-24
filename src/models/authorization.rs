use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Authorization {
    pub id: Uuid,
    pub user_id: Uuid,
    pub client_id: Uuid,
    pub code: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub used: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizationResponse {
    pub code: String,
    pub state: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: String,
    pub client_secret: String,
    pub refresh_token: Option<String>,
}

// 支持的授权类型
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum GrantType {
    AuthorizationCode,
    RefreshToken,
    ClientCredentials,
    Password,
}

impl From<&str> for GrantType {
    fn from(s: &str) -> Self {
        match s {
            "authorization_code" => GrantType::AuthorizationCode,
            "refresh_token" => GrantType::RefreshToken,
            "client_credentials" => GrantType::ClientCredentials,
            "password" => GrantType::Password,
            _ => panic!("不支持的授权类型"),
        }
    }
}

impl ToString for GrantType {
    fn to_string(&self) -> String {
        match self {
            GrantType::AuthorizationCode => "authorization_code".to_string(),
            GrantType::RefreshToken => "refresh_token".to_string(),
            GrantType::ClientCredentials => "client_credentials".to_string(),
            GrantType::Password => "password".to_string(),
        }
    }
} 