use crate::{config::OAuthConfig, models::TokenResponse, models::User};
use log::{error, info};
use serde_json;
use std::time::Duration;

/// 使用授权码获取令牌
pub async fn get_token_with_code(
    client: &reqwest::Client,
    config: &OAuthConfig,
    code: &str,
) -> Result<TokenResponse, String> {
    let token_url = format!("{}/api/oauth/token", config.auth_server_url);
    
    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("client_id", &config.client_id),
        ("client_secret", &config.client_secret),
        ("redirect_uri", &config.redirect_uri),
    ];

    info!("交换授权码获取令牌");

    match client
        .post(&token_url)
        .form(&params)
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(response) => {
            let status = response.status();
            
            if !status.is_success() {
                let error_text = response.text().await.unwrap_or_default();
                let error_msg = format!("令牌请求失败，状态码: {}, 错误: {}", status, error_text);
                error!("{}", error_msg);
                Err(error_msg)
            } else {
                match response.json::<TokenResponse>().await {
                    Ok(token_response) => {
                        info!("成功获取访问令牌");
                        Ok(token_response)
                    },
                    Err(e) => {
                        let error_msg = format!("解析令牌响应失败: {}", e);
                        error!("{}", error_msg);
                        Err(error_msg)
                    }
                }
            }
        },
        Err(e) => {
            let error_msg = format!("令牌请求发送失败: {}", e);
            error!("{}", error_msg);
            Err(error_msg)
        }
    }
}

/// 获取用户信息
pub async fn get_user_info(
    client: &reqwest::Client,
    config: &OAuthConfig,
    token: &str,
) -> Result<User, String> {
    let user_info_url = format!("{}/api/oauth/userinfo", config.auth_server_url);
    let max_retries = 3;
    let mut last_error = String::new();

    for attempt in 1..=max_retries {
        info!("获取用户信息 (尝试 {}/{})", attempt, max_retries);
        
        match client
            .get(&user_info_url)
            .header("Authorization", format!("Bearer {}", token))
            .timeout(Duration::from_secs(10))
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status();
                
                if !status.is_success() {
                    let error_text = response.text().await.unwrap_or_default();
                    last_error = format!("获取用户信息失败，状态码: {}, 错误: {}", status, error_text);
                    error!("{}", last_error);
                } else {
                    let response_text = match response.text().await {
                        Ok(text) => text,
                        Err(e) => {
                            last_error = format!("读取响应失败: {}", e);
                            error!("{}", last_error);
                            continue;
                        }
                    };
                    
                    info!("用户信息原始响应: {}", response_text);
                    
                    match serde_json::from_str::<User>(&response_text) {
                        Ok(user) => return Ok(user),
                        Err(e) => {
                            error!("用户信息解析错误: {}", e);
                            
                            let json_value: serde_json::Value = match serde_json::from_str(&response_text) {
                                Ok(value) => value,
                                Err(parse_err) => {
                                    last_error = format!("JSON解析失败: {}", parse_err);
                                    error!("{}", last_error);
                                    continue;
                                }
                            };
                            
                            let username = json_value.get("username")
                                .or_else(|| json_value.get("name"))
                                .or_else(|| json_value.get("preferred_username"))
                                .or_else(|| json_value.get("login"))
                                .and_then(|v| v.as_str())
                                .unwrap_or_default()
                                .to_string();
                            
                            let user = User {
                                id: json_value.get("id").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
                                username,
                                email: json_value.get("email").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
                                email_verified: json_value.get("email_verified").and_then(|v| v.as_bool()).unwrap_or(false),
                                avatar_url: json_value.get("avatar_url")
                                    .or_else(|| json_value.get("avatar"))
                                    .and_then(|v| v.as_str())
                                    .map(|s| s.to_string()),
                                avatar: json_value.get("avatar").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                picture: json_value.get("picture").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                created_at: json_value.get("created_at").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
                                last_login_at: json_value.get("last_login_at")
                                    .or_else(|| json_value.get("last_login"))
                                    .and_then(|v| v.as_str())
                                    .map(|s| s.to_string()),
                                is_active: json_value.get("is_active").and_then(|v| v.as_bool()).unwrap_or(true),
                                recent_login_count: json_value.get("recent_login_count").and_then(|v| v.as_i64()),
                            };
                            
                            return Ok(user);
                        }
                    }
                }
            },
            Err(e) => {
                last_error = format!("请求用户信息失败 (尝试 {}/{}): {}", attempt, max_retries, e);
                error!("{}", last_error);
            }
        }

        if attempt < max_retries {
            let delay = Duration::from_millis(500 * attempt as u64);
            info!("等待 {}ms 后重试获取用户信息", delay.as_millis());
            tokio::time::sleep(delay).await;
        }
    }

    Err(format!("获取用户信息失败，已重试 {} 次。最后错误: {}", max_retries, last_error))
} 