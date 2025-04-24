use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

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
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientCreate {
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub allowed_grant_types: Vec<String>,
    pub allowed_scopes: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientResponse {
    pub id: Uuid,
    pub name: String,
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    pub allowed_grant_types: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
}

impl From<Client> for ClientResponse {
    fn from(client: Client) -> Self {
        Self {
            id: client.id,
            name: client.name,
            client_id: client.client_id,
            redirect_uris: client.redirect_uris,
            allowed_grant_types: client.allowed_grant_types,
            allowed_scopes: client.allowed_scopes,
            created_at: client.created_at,
        }
    }
} 