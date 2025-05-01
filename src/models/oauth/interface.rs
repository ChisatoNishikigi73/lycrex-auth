use uuid::Uuid;
use sqlx::PgPool;
use serde::Serialize;
use crate::models::User;

/// OAuth响应接口
/// 
/// 统一处理不同OAuth提供商的响应格式
pub trait OAuthResponse: Sized + Serialize {
    /// 从User对象创建OAuth响应
    fn from_user(user: &User) -> Self;
    
    /// 获取响应中的用户ID (字符串格式)
    #[allow(unused)]
    fn get_id_str(&self) -> String;
    
    /// 适配某些系统可能需要数字格式的ID
    #[allow(unused)]
    fn get_id_num(&self) -> Result<i64, String> {
        // 尝试将字符串ID转换为数字
        self.get_id_str().parse::<i64>().map_err(|_| "ID不能转换为数字".to_string())
    }
    
    /// 对响应进行后处理，可用于需要异步操作的额外数据填充
    /// 
    /// 默认实现简单返回self不做任何处理
    /// 子类可以重写此方法实现异步数据填充
    #[allow(unused)]
    async fn post_process(self, user_id: &Uuid, db: &PgPool) -> Result<Self, String> {
        Ok(self)
    }
}

/// 所有支持的OAuth响应类型
#[derive(Serialize)]
#[serde(untagged)]
pub enum OAuthResponseType {
    OpenId(crate::models::oauth::openid::OpenIdUserResponse),
    Gitea(crate::models::oauth::gitea::GiteaUserResponse),
    Test(crate::models::oauth::test::TestUserResponse),
    Admin(crate::models::oauth::admin::AdminUserResponse),
    Lycrex(crate::models::oauth::lycrex::LycrexUserResponse),
    Casdoor(crate::models::oauth::casdoor::CasdoorUserResponse),
}

/// 处理OAuth响应的帮助函数
pub struct OAuthResponseHandler;

impl OAuthResponseHandler {
    /// 检查指定的响应类型是否是已知的OAuth响应类型
    /// 
    /// # 参数
    /// * `response_type` - 要检查的响应类型字符串
    /// 
    /// # 返回值
    /// * `true` - 如果是已知的OAuth响应类型
    /// * `false` - 如果不是已知的OAuth响应类型
    pub fn is_known_response_type(response_type: &str) -> bool {
        matches!(response_type, 
            "openid" | "gitea" | "test" | "admin" | "lycrex" | "casdoor")
    }

    /// 从用户ID查询用户信息
    pub async fn get_user_by_id(user_id: &str, db: &PgPool) -> Result<User, String> {
        // 验证用户ID格式
        let uuid = match Uuid::parse_str(user_id) {
            Ok(id) => id,
            Err(_) => return Err("无效的用户ID格式".to_string()),
        };
        
        // 从数据库获取用户
        match sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
            .bind(uuid)
            .fetch_one(db)
            .await {
                Ok(user) => Ok(user),
                Err(e) => Err(format!("数据库查询失败: {}", e)),
            }
    }

    /// 从用户ID创建指定类型的响应
    pub async fn create_response_of_type<T: OAuthResponse>(user_id: &str, db: &PgPool) -> Result<T, String> {
        let user = Self::get_user_by_id(user_id, db).await?;
        Ok(T::from_user(&user))
    }
    
    /// 根据响应类型创建对应的响应对象
    pub async fn create_response(response_type: &str, user_id: &str, db: &PgPool) 
        -> Result<OAuthResponseType, String> {
        
        // 验证用户ID格式
        let uuid = match Uuid::parse_str(user_id) {
            Ok(id) => id,
            Err(_) => return Err("无效的用户ID格式".to_string()),
        };
        
        match response_type {
            "openid" => {
                let resp = Self::create_response_of_type::<crate::models::oauth::openid::OpenIdUserResponse>(user_id, db).await?;
                let processed_resp = resp.post_process(&uuid, db).await?;
                Ok(OAuthResponseType::OpenId(processed_resp))
            },
            "gitea" => {
                let resp = Self::create_response_of_type::<crate::models::oauth::gitea::GiteaUserResponse>(user_id, db).await?;
                let processed_resp = resp.post_process(&uuid, db).await?;
                Ok(OAuthResponseType::Gitea(processed_resp))
            },
            "test" => {
                let resp = Self::create_response_of_type::<crate::models::oauth::test::TestUserResponse>(user_id, db).await?;
                let processed_resp = resp.post_process(&uuid, db).await?;
                Ok(OAuthResponseType::Test(processed_resp))
            },
            "admin" => {
                let resp = Self::create_response_of_type::<crate::models::oauth::admin::AdminUserResponse>(user_id, db).await?;
                let processed_resp = resp.post_process(&uuid, db).await?;
                Ok(OAuthResponseType::Admin(processed_resp))
            },
            "lycrex" => {
                let resp = Self::create_response_of_type::<crate::models::oauth::lycrex::LycrexUserResponse>(user_id, db).await?;
                let processed_resp = resp.post_process(&uuid, db).await?;
                Ok(OAuthResponseType::Lycrex(processed_resp))
            },
            "casdoor" => {
                let resp = Self::create_response_of_type::<crate::models::oauth::casdoor::CasdoorUserResponse>(user_id, db).await?;
                let processed_resp = resp.post_process(&uuid, db).await?;
                Ok(OAuthResponseType::Casdoor(processed_resp))
            },
            _ => Err(format!("不支持的响应类型: {}", response_type)),
        }
    }
} 