use serde::{Deserialize, Serialize};
use crate::models::User;
use crate::models::oauth::interface::OAuthResponse;
use uuid;
use sqlx;

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

// 实现OAuthResponse接口
impl OAuthResponse for CasdoorUserResponse {
    fn from_user(user: &User) -> Self {
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
            avatar: user.avatar_url.clone(),
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
    
    fn get_id_str(&self) -> String {
        self.id.clone()
    }
    
    // 增加一个后处理方法，设置一些额外的字段
    async fn post_process(mut self, user_id: &uuid::Uuid, db: &sqlx::PgPool) -> Result<Self, String> {
        // 使用User结构体查询用户信息
        match sqlx::query_as::<_, crate::models::User>("SELECT * FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(db)
            .await
        {
            Ok(Some(user)) => {
                // 根据一定规则判断是否为管理员 (例如特定的邮箱后缀)
                let is_admin = user.email.ends_with("@admin.lycrex.com") || 
                               user.username == "admin" ||
                               user.email == "admin@example.com";
                
                self.is_admin = Some(is_admin);
                self.is_global_admin = Some(is_admin);
                
                // 设置电话号码字段（如果有相关信息）
                self.phone = Some("未设置".to_string());
                
                // 如果是管理员，还可以设置一些特殊标签
                if is_admin {
                    self.tag = Some("admin".to_string());
                    self.score = Some(100); // 管理员得分更高
                } else {
                    self.tag = Some("user".to_string());
                    self.score = Some(10);  // 普通用户得分
                }
                
                Ok(self)
            },
            Ok(None) => {
                log::warn!("用户 {} 未找到，使用默认的Casdoor响应", user_id);
                Ok(self)
            },
            Err(e) => {
                log::warn!("查询用户 {} 信息失败: {}", user_id, e);
                Ok(self) // 返回原始响应
            }
        }
    }
}

/// 从我们的用户模型转换为Casdoor兼容的响应 (保持向后兼容)
impl From<User> for CasdoorUserResponse {
    fn from(user: User) -> Self {
        Self::from_user(&user)
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