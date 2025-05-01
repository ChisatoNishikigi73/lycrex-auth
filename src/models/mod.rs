/// 用户模型
pub mod user;
/// 客户端应用模型
pub mod client;
/// 访问令牌模型
pub mod token;
/// 授权码模型
pub mod authorization;
/// OAuth提供商模型
pub mod oauth;
/// 登录统计模型
pub mod login_stats;
 
pub use user::*;
pub use client::*;
pub use token::*;
pub use authorization::*; 
pub use login_stats::*;

// 导出各种OAuth响应结构体
#[allow(unused)]
pub use oauth::openid::OpenIdUserResponse;
#[allow(unused)]
pub use oauth::gitea::GiteaUserResponse;
#[allow(unused)]
pub use oauth::test::TestUserResponse;
#[allow(unused)]
pub use oauth::admin::AdminUserResponse;
#[allow(unused)]
pub use oauth::casdoor::CasdoorUserResponse;
#[allow(unused)]
pub use oauth::lycrex::LycrexUserResponse;

// 导出OAuth响应接口
#[allow(unused)]
pub use oauth::interface::{OAuthResponse, OAuthResponseHandler}; 