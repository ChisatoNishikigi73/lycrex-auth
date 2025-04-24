use bcrypt::{hash, verify, DEFAULT_COST};

use crate::errors::AppError;

/// 对密码进行哈希处理
/// 
/// # 参数
/// * `password` - 需要哈希的明文密码
/// 
/// # 返回
/// * `Result<String, AppError>` - 成功返回哈希后的密码字符串，失败返回错误
pub fn hash_password(password: &str) -> Result<String, AppError> {
    hash(password, DEFAULT_COST).map_err(|e| {
        AppError::InternalServerError(format!("密码哈希失败: {}", e))
    })
}

/// 验证密码是否与哈希值匹配
/// 
/// # 参数
/// * `password` - 需要验证的明文密码
/// * `hash` - 存储的密码哈希值
/// 
/// # 返回
/// * `Result<bool, AppError>` - 成功返回验证结果，失败返回错误
pub fn verify_password(password: &str, hash: &str) -> Result<bool, AppError> {
    verify(password, hash).map_err(|e| {
        AppError::InternalServerError(format!("密码验证失败: {}", e))
    })
} 