use serde::Deserialize;
use config::{Config as ConfigCrate, ConfigError, Environment, File};
use log::info;
use std::sync::OnceLock;

/// 服务器配置
#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    /// 服务器监听地址
    pub host: String,
    /// 服务器监听端口
    pub port: u16,
    /// 用于会话和安全功能的密钥
    pub secret_key: String,
}

/// 数据库配置
#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    /// 数据库连接URL
    pub url: String,
}

/// CORS跨域配置
#[derive(Debug, Deserialize, Clone)]
pub struct CorsConfig {
    /// 允许的来源域名列表
    pub allowed_origins: Vec<String>,
}

/// 日志配置
#[derive(Debug, Deserialize, Clone)]
pub struct LogConfig {
    /// 日志级别
    pub level: String,
    /// 日志格式
    pub format: String,
}

/// 安全配置
#[derive(Debug, Deserialize, Clone)]
pub struct SecurityConfig {
    /// 访问令牌生命周期（秒）
    pub access_token_lifetime: i64,
    /// 刷新令牌生命周期（天）
    pub refresh_token_lifetime: i64,
    /// 授权码生命周期（秒）
    pub authorization_code_lifetime: i64,
    /// 是否需要邮箱验证才能登录
    pub require_email_verification: bool,
}

/// 管理员配置
#[derive(Debug, Deserialize, Clone)]
pub struct AdminConfig {
    /// 管理员密码，用于管理后台登录和添加/删除提供方
    pub password: String,
}

/// 应用程序全局配置
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// 服务器配置
    pub server: ServerConfig,
    /// 数据库配置
    pub database: DatabaseConfig,
    /// CORS配置
    pub cors: CorsConfig,
    /// 日志配置
    pub log: LogConfig,
    /// 安全配置
    pub security: SecurityConfig,
    /// 管理员配置
    pub admin: AdminConfig,
}

// 全局静态配置实例
static CONFIG: OnceLock<Config> = OnceLock::new();

impl Config {
    /// 加载配置
    /// 
    /// 从config/app.toml文件加载配置
    pub fn load() -> Result<Self, ConfigError> {
        // 构建配置
        let builder = ConfigCrate::builder()
            // 使用config/app.toml作为唯一配置文件
            .add_source(File::with_name("config/app.toml").required(false))
            // 仍然保留环境变量方式，确保可以通过环境变量覆盖配置
            .add_source(Environment::with_prefix("APP").separator("_"));
            
        // 构建并解析配置
        let config = builder.build()?;
        config.try_deserialize()
    }

    /// 从环境变量和配置文件加载配置（向后兼容）
    #[allow(dead_code)]
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::load()
    }
    
    /// 获取全局配置实例
    /// 
    /// 如果全局配置尚未初始化，此方法将尝试加载它。
    /// 如果加载失败，将返回默认配置。
    /// 
    /// # 返回
    /// 返回全局配置的引用
    pub fn get_global() -> &'static Self {
        CONFIG.get_or_init(|| {
            match Self::load() {
                Ok(config) => {
                    info!("已从config/app.toml加载配置");
                    config
                },
                Err(e) => {
                    // 如果加载失败，使用默认配置并记录错误
                    log::error!("从config/app.toml加载配置失败: {}", e);
                    log::warn!("使用默认配置");
                    Self::default()
                }
            }
        })
    }
}

impl Default for Config {
    /// 默认配置
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
                secret_key: "开发环境密钥，请在生产环境中替换".to_string(),
            },
            database: DatabaseConfig {
                url: "postgres://postgres:postgres@localhost/lycrex_auth".to_string(),
            },
            cors: CorsConfig {
                allowed_origins: vec![
                    "http://localhost:3000".to_string(),
                    "http://127.0.0.1:3000".to_string(),
                    "http://127.0.0.1:8080".to_string(),
                    "http://localhost:8080".to_string(),
                ],
            },
            log: LogConfig {
                level: "info".to_string(),
                format: "default".to_string(),
            },
            security: SecurityConfig {
                access_token_lifetime: 3600,
                refresh_token_lifetime: 30,
                authorization_code_lifetime: 600,
                require_email_verification: true, // 默认需要邮箱验证
            },
            admin: AdminConfig {
                password: "admin123".to_string(), // 默认密码，生产环境应该更改
            },
        }
    }
} 