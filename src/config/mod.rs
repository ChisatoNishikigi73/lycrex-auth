use serde::Deserialize;
use config::{Config as ConfigCrate, ConfigError, Environment, File};
use log::info;
use std::sync::OnceLock;

/// 服务器配置
/// 
/// 包含服务器基本设置，如监听地址、端口和安全密钥
#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    /// 服务器监听地址
    pub host: String,
    /// 服务器监听端口
    pub port: u16,
    /// 用于会话和安全功能的密钥
    pub secret_key: String,
    /// 公共URL
    pub public_url: String,
}

/// 数据库配置
/// 
/// 包含数据库连接信息
#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    /// 数据库连接URL
    pub url: String,
}

/// CORS跨域配置
/// 
/// 定义跨域资源共享的规则和允许的来源
#[derive(Debug, Deserialize, Clone)]
pub struct CorsConfig {
    /// 允许的来源域名列表
    pub allowed_origins: Vec<String>,
}

/// 日志配置
/// 
/// 控制日志输出的级别和格式
#[derive(Debug, Deserialize, Clone)]
pub struct LogConfig {
    /// 日志级别（debug, info, warn, error）
    pub level: String,
    /// 日志格式（default, json等）
    pub format: String,
}

/// 安全配置
/// 
/// 定义各种安全相关设置，如令牌生命周期和验证要求
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
/// 
/// 定义管理后台的访问控制
#[derive(Debug, Deserialize, Clone)]
pub struct AdminConfig {
    /// 管理员密码，用于管理后台登录和添加/删除提供方
    pub password: String,
}

/// 应用程序全局配置
/// 
/// 包含所有子配置模块，为整个应用提供配置信息
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

/// 配置加载错误处理
/// 
/// 处理配置加载过程中可能发生的错误，并返回适当的日志消息
fn handle_config_error(error: &ConfigError) -> String {
    match error {
        ConfigError::Foreign(err) => format!("外部错误: {}", err),
        ConfigError::Message(msg) => format!("配置错误: {}", msg),
        ConfigError::NotFound(path) => format!("找不到配置文件: {}", path),
        ConfigError::PathParse { cause } => format!("路径解析错误: {:?}", cause),
        ConfigError::FileParse { uri, cause } => format!("文件解析错误: {:?}，原因: {}", uri, cause),
        ConfigError::Type { origin, unexpected, expected, .. } => {
            format!("类型错误，来源: {:?}，预期: {}，实际: {}", origin, expected, unexpected)
        }
        _ => format!("未知配置错误: {}", error),
    }
}

impl Config {
    /// 加载配置
    /// 
    /// 从config/app.toml文件加载配置，如果找不到配置文件或者解析出错
    /// 将会返回详细的错误信息
    /// 
    /// # 返回
    /// * `Ok(Config)` - 成功加载的配置
    /// * `Err(ConfigError)` - 配置加载错误
    pub fn load() -> Result<Self, ConfigError> {
        log::debug!("开始加载配置...");
        
        // 构建配置
        let builder = ConfigCrate::builder()
            // 使用config/app.toml作为唯一配置文件
            .add_source(File::with_name("config/app.toml").required(false))
            // 仍然保留环境变量方式，确保可以通过环境变量覆盖配置
            .add_source(Environment::with_prefix("APP").separator("_"));
            
        // 构建并解析配置
        match builder.build() {
            Ok(config) => {
                log::debug!("配置文件已成功读取");
                match config.try_deserialize() {
                    Ok(parsed) => {
                        log::debug!("配置解析成功");
                        Ok(parsed)
                    },
                    Err(e) => {
                        log::error!("解析配置时出错: {}", handle_config_error(&e));
                        Err(e)
                    }
                }
            },
            Err(e) => {
                log::error!("读取配置文件时出错: {}", handle_config_error(&e));
                Err(e)
            }
        }
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
                    log::debug!("配置内容概览: 服务器端口={}, 日志级别={}, 需要邮箱验证={}", 
                        config.server.port, config.log.level, config.security.require_email_verification);
                    config
                },
                Err(e) => {
                    // 如果加载失败，使用默认配置并记录错误
                    log::error!("从config/app.toml加载配置失败: {}", handle_config_error(&e));
                    log::warn!("使用默认配置，这可能不适合生产环境");
                    Self::default()
                }
            }
        })
    }
    
    /// 检查是否使用了开发环境配置
    /// 
    /// 用于在应用启动时检查是否使用了不适合生产环境的默认配置
    /// 
    /// # 返回
    /// * `true` - 使用了开发环境配置
    /// * `false` - 使用了自定义配置
    #[allow(unused)]
    pub fn is_development_config(&self) -> bool {
        self.server.secret_key == "开发环境密钥，请在生产环境中替换" &&
        self.admin.password == "admin123"
    }
}

impl Default for Config {
    /// 默认配置
    /// 
    /// 提供一个基本的开发环境配置，不应在生产环境中使用
    fn default() -> Self {
        let config = Self {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
                secret_key: "开发环境密钥，请在生产环境中替换".to_string(),
                public_url: "https://oauth.lycrex.com".to_string(),
            },
            database: DatabaseConfig {
                url: "postgres://postgres:postgres@localhost/lycrex_auth".to_string(),
            },
            cors: CorsConfig {
                allowed_origins: vec![
                    "http://localhost:3000".to_string(),
                    "http://127.0.0.1:3000".to_string(),
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
        };
        
        log::warn!("使用默认配置：这些设置仅供开发使用，不适合生产环境");
        log::debug!("默认配置：监听地址={}:{}, 数据库={}", 
            config.server.host, config.server.port, config.database.url);
        
        config
    }
} 