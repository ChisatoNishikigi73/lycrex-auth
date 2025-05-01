use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// 客户端登录信息
#[derive(Debug, Serialize)]
pub struct ClientLoginInfo {
    pub client_id: Uuid,
    pub client_name: String, 
    pub login_count: i64,
    pub last_login: String,
    pub client_type: Option<String>,
}

/// 客户端登录统计（API响应）
#[derive(Debug, Serialize)]
pub struct ClientLoginStat {
    pub client_name: String,
    pub login_count: i32,
    pub last_login: DateTime<Utc>,
}

/// 登录记录响应结构体
#[derive(Debug, Serialize)]
pub struct LoginHistoryResponse {
    pub total_logins: i32,
    pub start_date: DateTime<Utc>,
    pub end_date: DateTime<Utc>,
    pub login_records: Vec<LoginRecord>,
    pub client_stats: Vec<ClientLoginStat>,
}

/// 登录统计响应结构体（不包含详细记录）
#[derive(Debug, Serialize)]
pub struct LoginStatsResponse {
    pub total_logins: i32,
    pub start_date: DateTime<Utc>,
    pub end_date: DateTime<Utc>,
    pub client_stats: Vec<ClientLoginStat>,
}

/// 单条登录记录
#[derive(Debug, Serialize)]
pub struct LoginRecord {
    pub id: Uuid,
    pub client_name: String,
    pub login_time: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub is_active: bool,
}

/// 登录历史查询参数
#[derive(Debug, Deserialize)]
pub struct LoginHistoryQuery {
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub days: Option<i32>,
} 