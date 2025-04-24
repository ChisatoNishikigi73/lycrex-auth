use rand::{distributions::Alphanumeric, Rng};
use uuid::Uuid;

/// 生成指定长度的随机字符串
pub fn generate_random_string(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

/// 生成随机客户端ID，用于OAuth客户端标识
pub fn generate_client_id() -> String {
    generate_random_string(32)
}

/// 生成随机客户端密钥，用于OAuth客户端认证
pub fn generate_client_secret() -> String {
    generate_random_string(64)
}

/// 生成随机授权码，用于OAuth授权码流程
pub fn generate_authorization_code() -> String {
    generate_random_string(40)
}

/// 生成随机访问令牌，结合UUID和随机字符串
#[allow(dead_code)]
pub fn generate_token() -> String {
    Uuid::new_v4().to_string().replace("-", "") + &generate_random_string(32)
} 