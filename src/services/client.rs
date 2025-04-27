use chrono::Utc;
use sqlx::{PgPool, query, query_as};
use uuid::Uuid;

use crate::errors::{AppError, AppResult};
use crate::models::{Client, ClientCreate, ClientResponse, ClientType};
use crate::utils::random;

pub async fn create_client(
    client: &ClientCreate,
    user_id: Option<Uuid>,
    db: &PgPool,
) -> AppResult<Client> {
    let now = Utc::now();
    let client_id = Uuid::new_v4();
    
    // 生成客户端ID和密钥
    let client_id_str = random::generate_client_id();
    let client_secret = random::generate_client_secret();
    
    // 使用提供的客户端类型或默认为OpenId
    let client_type = client.client_type.unwrap_or_default();
    
    // 创建客户端
    let client = query_as::<_, Client>(
        r#"
        INSERT INTO clients (
            id, name, client_id, client_secret, redirect_uris, 
            allowed_grant_types, allowed_scopes, user_id, created_at, updated_at, client_type
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING *
        "#)
    .bind(client_id)
    .bind(&client.name)
    .bind(&client_id_str)
    .bind(&client_secret)
    .bind(&client.redirect_uris)
    .bind(&client.allowed_grant_types)
    .bind(&client.allowed_scopes)
    .bind(user_id)
    .bind(now)
    .bind(now)
    .bind(client_type)
    .fetch_one(db)
    .await
    .map_err(AppError::DatabaseError)?;
    
    Ok(client)
}

/// 使用自定义client_id和client_secret创建提供方客户端
pub async fn create_provider_client(
    client: &ClientCreate,
    client_id_str: &str,
    client_secret: &str,
    user_id: Option<Uuid>,
    db: &PgPool,
) -> AppResult<Client> {
    let now = Utc::now();
    let client_id = Uuid::new_v4();
    
    // 检查client_id是否已存在
    let exists = query("SELECT 1 FROM clients WHERE client_id = $1")
        .bind(client_id_str)
        .fetch_optional(db)
        .await
        .map_err(AppError::DatabaseError)?
        .is_some();
        
    if exists {
        return Err(AppError::BadRequest("客户端ID已存在".to_string()));
    }
    
    // 使用提供的客户端类型或默认为OpenId
    let client_type = client.client_type.unwrap_or_default();
    
    // 创建客户端
    let client = query_as::<_, Client>(
        r#"
        INSERT INTO clients (
            id, name, client_id, client_secret, redirect_uris, 
            allowed_grant_types, allowed_scopes, user_id, created_at, updated_at, client_type
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING *
        "#)
    .bind(client_id)
    .bind(&client.name)
    .bind(client_id_str)
    .bind(client_secret)
    .bind(&client.redirect_uris)
    .bind(&client.allowed_grant_types)
    .bind(&client.allowed_scopes)
    .bind(user_id)
    .bind(now)
    .bind(now)
    .bind(client_type)
    .fetch_one(db)
    .await
    .map_err(AppError::DatabaseError)?;
    
    Ok(client)
}

pub async fn get_client_by_id(id: Uuid, db: &PgPool) -> AppResult<ClientResponse> {
    let client = query_as::<_, Client>(r#"SELECT * FROM clients WHERE id = $1"#)
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::DatabaseError)?
    .ok_or_else(|| AppError::NotFound("客户端未找到".to_string()))?;
    
    Ok(ClientResponse::from(client))
}

/// 获取所有客户端
pub async fn get_all_clients(db: &PgPool) -> AppResult<Vec<ClientResponse>> {
    let clients = query_as::<_, Client>(r#"SELECT * FROM clients ORDER BY created_at DESC"#)
        .fetch_all(db)
        .await
        .map_err(AppError::DatabaseError)?;
    
    Ok(clients.into_iter().map(ClientResponse::from).collect())
}

pub async fn get_clients_by_user(user_id: Uuid, db: &PgPool) -> AppResult<Vec<ClientResponse>> {
    let clients = query_as::<_, Client>(r#"SELECT * FROM clients WHERE user_id = $1"#)
    .bind(user_id)
    .fetch_all(db)
    .await
    .map_err(AppError::DatabaseError)?;
    
    Ok(clients.into_iter().map(ClientResponse::from).collect())
}

pub async fn update_client(
    id: Uuid,
    name: Option<String>,
    redirect_uris: Option<Vec<String>>,
    allowed_scopes: Option<Vec<String>>,
    client_type: Option<ClientType>,
    db: &PgPool,
) -> AppResult<ClientResponse> {
    // 检查客户端是否存在
    let client = query_as::<_, Client>(r#"SELECT * FROM clients WHERE id = $1"#)
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::DatabaseError)?
    .ok_or_else(|| AppError::NotFound("客户端未找到".to_string()))?;
    
    // 更新字段
    let name = name.unwrap_or(client.name);
    let redirect_uris = redirect_uris.unwrap_or(client.redirect_uris);
    let allowed_scopes = allowed_scopes.unwrap_or(client.allowed_scopes);
    let client_type = client_type.unwrap_or(client.client_type);
    let now = Utc::now();
    
    // 更新客户端
    let updated_client = query_as::<_, Client>(
        r#"
        UPDATE clients
        SET name = $1, redirect_uris = $2, allowed_scopes = $3, updated_at = $4, client_type = $5
        WHERE id = $6
        RETURNING *
        "#)
    .bind(&name)
    .bind(&redirect_uris)
    .bind(&allowed_scopes)
    .bind(now)
    .bind(client_type)
    .bind(id)
    .fetch_one(db)
    .await
    .map_err(AppError::DatabaseError)?;
    
    Ok(ClientResponse::from(updated_client))
}

pub async fn delete_client(id: Uuid, db: &PgPool) -> AppResult<()> {
    // 检查客户端是否存在
    let exists = query(r#"SELECT id FROM clients WHERE id = $1"#)
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::DatabaseError)?
    .is_some();
    
    if !exists {
        return Err(AppError::NotFound("客户端未找到".to_string()));
    }
    
    // 删除客户端
    query(r#"DELETE FROM clients WHERE id = $1"#)
    .bind(id)
    .execute(db)
    .await
    .map_err(AppError::DatabaseError)?;
    
    Ok(())
}

pub async fn update_client_credentials(
    id: Uuid,
    client_id_str: Option<String>,
    client_secret: Option<String>,
    db: &PgPool,
) -> AppResult<ClientResponse> {
    // 检查客户端是否存在
    let client = query_as::<_, Client>(r#"SELECT * FROM clients WHERE id = $1"#)
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::DatabaseError)?
    .ok_or_else(|| AppError::NotFound("客户端未找到".to_string()))?;
    
    // 如果提供了新的client_id，检查它是否与其他客户端冲突
    if let Some(ref new_client_id) = client_id_str {
        if new_client_id != &client.client_id {
            let exists = query("SELECT 1 FROM clients WHERE client_id = $1 AND id != $2")
                .bind(new_client_id)
                .bind(id)
                .fetch_optional(db)
                .await
                .map_err(AppError::DatabaseError)?
                .is_some();
                
            if exists {
                return Err(AppError::BadRequest("客户端ID已被其他客户端使用".to_string()));
            }
        }
    }
    
    // 准备更新字段
    let client_id_value = client_id_str.as_deref().unwrap_or(&client.client_id);
    let client_secret_value = client_secret.as_deref().unwrap_or(&client.client_secret);
    let now = Utc::now();
    
    // 更新客户端凭据
    let updated_client = query_as::<_, Client>(
        r#"
        UPDATE clients
        SET client_id = $1, client_secret = $2, updated_at = $3
        WHERE id = $4
        RETURNING *
        "#)
    .bind(client_id_value)
    .bind(client_secret_value)
    .bind(now)
    .bind(id)
    .fetch_one(db)
    .await
    .map_err(AppError::DatabaseError)?;
    
    Ok(ClientResponse::from(updated_client))
} 