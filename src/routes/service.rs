use actix_web::{get, web, HttpResponse, Responder};
use sqlx::PgPool;
use uuid::Uuid;
use crate::services::user as user_service;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;

/// 图像查询参数
#[derive(Deserialize)]
struct ImageParams {
    /// 图像宽度
    width: Option<u32>,
    /// 图像高度
    height: Option<u32>,
}

/// 配置服务相关路由
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/service")
            .service(get_user_avatar)
    );
}

/// 根据UUID获取用户头像
#[get("/{uuid}/avatar.png")]
async fn get_user_avatar(
    path: web::Path<String>,
    query: web::Query<ImageParams>,
    db: web::Data<PgPool>,
) -> impl Responder {
    let uuid_str = path.into_inner();
    
    // 获取图像尺寸参数
    let width = query.width;
    let height = query.height;
    
    // 尝试解析完整UUID
    let user_id = match Uuid::parse_str(&uuid_str) {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::BadRequest()
                .content_type("application/json")
                .json(serde_json::json!({ "error": "无效的用户ID" }));
        }
    };
    
    // 获取用户信息
    match user_service::find_user_by_id(user_id, &db).await {
        Ok(Some(user)) => {
            // 检查用户是否有头像
            if let Some(avatar_base64) = user.avatar {
                // 尝试将base64解码为图像数据
                match decode_avatar_base64(&avatar_base64) {
                    Ok(image_data) => {
                        // 尺寸调整标记，用于生成ETag
                        let size_tag = match (width, height) {
                            (Some(w), Some(h)) => format!("_{}x{}", w, h),
                            (Some(w), None) => format!("_{}x", w),
                            (None, Some(h)) => format!("_x{}", h),
                            (None, None) => "".to_string(),
                        };
                        
                        // 计算ETag (包含尺寸信息)
                        let etag = format!("\"{}{}_{}_{}\"", 
                            user.id, 
                            size_tag,
                            image_data.len(), 
                            user.updated_at.timestamp()
                        );
                        
                        // 注意：这里只是添加了尺寸调整的接口，不实现具体的图像处理
                        // 实际项目中，应该使用图像处理库(如image crate)来调整图像尺寸
                        
                        // 设置缓存头，一天的缓存时间
                        HttpResponse::Ok()
                            .content_type("image/png")
                            .append_header(("ETag", etag))
                            .append_header(("Cache-Control", "public, max-age=86400"))
                            .body(image_data)
                    },
                    Err(_) => {
                        HttpResponse::InternalServerError()
                            .content_type("application/json")
                            .json(serde_json::json!({ "error": "无法解码头像数据" }))
                    }
                }
            } else {
                // 用户没有头像，返回404
                HttpResponse::NotFound()
                    .content_type("application/json")
                    .json(serde_json::json!({ "error": "用户没有头像" }))
            }
        },
        Ok(None) => {
            // 用户不存在，返回404
            HttpResponse::NotFound()
                .content_type("application/json")
                .json(serde_json::json!({ "error": "用户不存在" }))
        },
        Err(e) => {
            // 数据库错误，返回500
            HttpResponse::InternalServerError()
                .content_type("application/json")
                .json(serde_json::json!({ "error": format!("服务器错误: {}", e) }))
        }
    }
}

/// 解码Base64编码的头像数据
fn decode_avatar_base64(avatar_base64: &str) -> Result<Vec<u8>, base64::DecodeError> {
    // 检查是否已经包含data:前缀
    let base64_data = if avatar_base64.starts_with("data:image") {
        // 提取实际的base64部分
        avatar_base64.split(',').nth(1).unwrap_or(avatar_base64)
    } else {
        avatar_base64
    };
    
    // 解码base64数据
    STANDARD.decode(base64_data)
} 