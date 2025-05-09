use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// 客户端类型枚举
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, sqlx::Type)]
#[sqlx(type_name = "client_type", rename_all = "lowercase")]
pub enum ClientType {
    /// OpenID Connect 标准
    OpenId,
    /// Gitea 兼容
    Gitea,
    /// Casdoor 兼容
    Casdoor,
    /// Lycrex 类型
    Lycrex,
    /// 测试客户端
    Test,
}

impl ClientType {
    /// 将ClientType转换为对应的响应类型字符串
    /// 
    /// 这个方法用于统一处理ClientType到OAuth响应类型的映射，
    /// 避免在代码的多个地方重复相同的映射逻辑。
    pub fn to_response_type(&self) -> &'static str {
        match self {
            ClientType::OpenId => "openid",
            ClientType::Gitea => "gitea",
            ClientType::Casdoor => "casdoor",
            ClientType::Lycrex => "lycrex",
            ClientType::Test => "test",
        }
    }
}

impl Default for ClientType {
    fn default() -> Self {
        ClientType::OpenId
    }
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Client {
    pub id: Uuid,
    pub name: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uris: Vec<String>,
    pub allowed_grant_types: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub user_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[sqlx(default)]
    pub client_type: ClientType,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientCreate {
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub allowed_grant_types: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub client_type: Option<ClientType>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientResponse {
    pub id: Uuid,
    pub name: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uris: Vec<String>,
    pub allowed_grant_types: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub client_type: ClientType,
}

impl From<Client> for ClientResponse {
    fn from(client: Client) -> Self {
        Self {
            id: client.id,
            name: client.name,
            client_id: client.client_id,
            client_secret: client.client_secret,
            redirect_uris: client.redirect_uris,
            allowed_grant_types: client.allowed_grant_types,
            allowed_scopes: client.allowed_scopes,
            created_at: client.created_at,
            client_type: client.client_type,
        }
    }
} 