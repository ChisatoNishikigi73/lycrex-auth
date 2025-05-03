use std::env;

/// OAuth客户端配置
pub struct OAuthConfig {
    pub auth_server_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

impl OAuthConfig {
    /// 初始化OAuth配置
    pub fn new() -> Self {
        Self {
            auth_server_url: get_env_or_default("AUTH_SERVER_URL", "http://127.0.0.1:8080"),
            client_id: get_env_or_default("CLIENT_ID", "profile-client"),
            client_secret: get_env_or_default("CLIENT_SECRET", "profile-secret"),
            redirect_uri: get_env_or_default("REDIRECT_URI", "http://localhost:3000/auth/callback"),
        }
    }
}

impl Clone for OAuthConfig {
    fn clone(&self) -> Self {
        Self {
            auth_server_url: self.auth_server_url.clone(),
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            redirect_uri: self.redirect_uri.clone(),
        }
    }
}

/// 获取环境变量，如果不存在则使用默认值
pub fn get_env_or_default(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
} 