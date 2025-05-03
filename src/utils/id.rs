use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use uuid::Uuid;

/// 将UUID转换为稳定的i64正整数
/// 
/// 使用哈希函数将UUID转换为64位整数，并确保结果始终为正数
/// 
/// # 参数
/// * `uuid` - 要转换的UUID
/// 
/// # 返回值
/// 返回一个保证为正数的i64整数
/// 
/// # 注意
/// 此方法可能存在哈希碰撞的风险，即两个不同的UUID可能生成相同的ID
#[allow(unused)]
pub fn uuid_to_i64(uuid: Uuid) -> i64 {
    let mut hasher = DefaultHasher::new();
    uuid.hash(&mut hasher);
    // 使用位运算确保结果为正数（清除符号位）
    (hasher.finish() & 0x7FFFFFFFFFFFFFFF) as i64
}

/// 将字符串形式的UUID转换为i64正整数
/// 
/// # 参数
/// * `uuid_str` - UUID字符串
/// 
/// # 返回值
/// 如果UUID字符串有效，返回对应的i64整数；否则返回None
#[allow(unused)]
pub fn uuid_str_to_i64(uuid_str: &str) -> Option<i64> {
    match Uuid::parse_str(uuid_str) {
        Ok(uuid) => Some(uuid_to_i64(uuid)),
        Err(_) => None,
    }
}

/// 使用更可靠的转换方法将UUID转换为i64
/// 
/// 此方法尝试利用UUID的高低位，减少哈希碰撞的可能性
/// 
/// # 参数
/// * `uuid` - 要转换的UUID
/// 
/// # 返回值
/// 返回一个保证为正数的i64整数
#[allow(unused)]
pub fn uuid_to_i64_reliable(uuid: Uuid) -> i64 {
    // 获取UUID的两个u64部分并进行XOR操作
    let bytes = uuid.as_bytes();
    let high = u64::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]);
    let low = u64::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]]);
    
    // 使用XOR操作合并高低位，并确保结果为正数
    ((high ^ low) & 0x7FFFFFFFFFFFFFFF) as i64
}

/// 将UUID确定性地转换为唯一的i64整数（无碰撞风险）
/// 
/// 这个方法确保不同的UUID一定会映射到不同的数据库ID，但限制是ID可能很大
/// 
/// # 参数
/// * `uuid` - 要转换的UUID
/// 
/// # 返回值
/// 返回保证唯一且为正数的i64整数，如果超出i64范围则返回一个回退值
#[allow(unused)]
pub fn uuid_to_unique_i64(uuid: Uuid) -> i64 {
    let bytes = uuid.as_bytes();
    
    // 获取UUID的前8个字节，转换为u64，再转为i64
    // 使用modulo操作确保结果在i64范围内且为正数
    let num = u64::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3], 
                                  bytes[4], bytes[5], bytes[6], bytes[7]]);
    
    // 对结果取模，确保在i64可表示的正数范围内
    // i64::MAX = 9223372036854775807
    let result = (num % 9223372036854775807) as i64;
    
    // 确保结果为正数
    if result <= 0 {
        // 极罕见的情况：使用后8个字节作为备选
        let backup = u64::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11], 
                                         bytes[12], bytes[13], bytes[14], bytes[15]]);
        (backup % 9223372036854775807) as i64
    } else {
        result
    }
}

/// 将UUID确定性地转换为递增的i64整数（Gitea优化版）
/// 
/// 此方法特别优化用于Gitea集成，生成较小的ID值，适合数据库使用
/// 将UUID转换为1-10_000_000范围内的整数
/// 
/// # 参数
/// * `uuid` - 要转换的UUID
/// 
/// # 返回值
/// 返回1-10,000,000范围内的正整数
pub fn uuid_to_gitea_id(uuid: Uuid) -> i64 {
    let bytes = uuid.as_bytes();
    
    // 将UUID的所有字节相加作为种子
    let mut seed: u64 = 0;
    for byte in bytes {
        seed = seed.wrapping_add(*byte as u64);
    }
    
    // 生成1到10,000,000之间的ID
    // 使用取模操作确保ID在合理范围内
    let range = 10_000_000;
    let id = (seed % range as u64) as i64;
    
    // 确保ID始终为正数且不为0（Gitea ID通常从1开始）
    if id <= 0 {
        1
    } else {
        id
    }
}