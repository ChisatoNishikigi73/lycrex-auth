use actix_web::{get, web, HttpResponse, Responder};
use sqlx::PgPool;
use uuid::Uuid;
use crate::{config::Config, services::user as user_service};
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
#[get("/profile/{uuid}/avatar")]
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
                    Ok((image_data, content_type)) => {
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
                            .content_type(content_type)
                            .append_header(("ETag", etag))
                            .append_header(("Cache-Control", "public, max-age=86400"))
                            .body(image_data)
                    },
                    Err(e) => {
                        // 解码头像失败，返回错误信息
                        HttpResponse::BadRequest()
                            .content_type("application/json")
                            .json(serde_json::json!({ 
                                "error": "无法解码头像数据", 
                                "details": format!("不支持的头像格式或数据错误: {:?}", e)
                            }))
                    }
                }
            } else {
                // 用户没有头像，返回默认头像
                let default_avatar = get_default_avatar();
                match decode_avatar_base64(default_avatar) {
                    Ok((image_data, content_type)) => {
                        // 返回默认头像
                        HttpResponse::Ok()
                            .content_type(content_type)
                            .append_header(("Cache-Control", "public, max-age=86400"))
                            .body(image_data)
                    },
                    Err(_) => {
                        // 默认头像也解码失败，这是内部错误
                        HttpResponse::InternalServerError()
                            .content_type("application/json")
                            .json(serde_json::json!({ "error": "无法解码默认头像数据" }))
                    }
                }
            }
        },
        Ok(None) => {
            // 用户不存在，返回404
            HttpResponse::NotFound()
                .content_type("application/json")
                .json(serde_json::json!({ "error": "用户不存在" }))
        },
        Err(_) => {
            // 数据库错误，返回500
            HttpResponse::InternalServerError()
                .content_type("application/json")
                .json(serde_json::json!({ "error": "无法解码默认头像数据" }))
        }
    }
}

/// 解码Base64编码的头像数据
fn decode_avatar_base64(avatar_base64: &str) -> Result<(Vec<u8>, &'static str), base64::DecodeError> {
    // 检查是否包含data:image前缀，如果没有则返回错误
    if avatar_base64.starts_with("data:image") {
        // 从data URI中提取内容类型和数据
        let parts: Vec<&str> = avatar_base64.split(',').collect();
        let mime_part = parts.get(0).unwrap_or(&"");
        
        // 根据MIME类型设置内容类型
        let content_type = if mime_part.contains("image/gif") {
            "image/gif"
        } else if mime_part.contains("image/jpeg") || mime_part.contains("image/jpg") {
            "image/jpeg"
        } else {
            // 默认为PNG
            "image/png"
        };
        
        // 提取base64部分，如果不存在则使用原始字符串
        let data_part = parts.get(1).unwrap_or(&avatar_base64);
        // 解码base64数据
        STANDARD.decode(data_part).map(|data| (data, content_type))
    } else if avatar_base64.starts_with("R0lGOD") {
        // 特殊处理：如果是以GIF头部标识开始，但没有data:URI前缀
        STANDARD.decode(avatar_base64).map(|data| (data, "image/gif"))
    } else if avatar_base64.starts_with("iVBOR") {
        // 特殊处理：如果是以PNG头部标识开始，但没有data:URI前缀
        STANDARD.decode(avatar_base64).map(|data| (data, "image/png"))
    } else if avatar_base64.starts_with("/9j/") {
        // 特殊处理：如果是以JPEG头部标识开始，但没有data:URI前缀
        STANDARD.decode(avatar_base64).map(|data| (data, "image/jpeg"))
    } else {
        // 不支持的格式，返回解码错误
        Err(base64::DecodeError::InvalidLength)
    }
}

/// 获取默认头像base64编码 - 随机颜色和GIF版本
pub fn get_default_avatar() -> &'static str {
    // 包含静态图像和动态GIF的随机头像集合
    const AVATARS: [&str; 6] = [
        // 静态头像 (PNG格式)
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAAXNSR0IArs4c6QAAAA1JREFUGFdj+O/g8B8ABkACf3lhiWUAAAAASUVORK5CYII=", // 红色
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAAXNSR0IArs4c6QAAAA1JREFUGFdjuO/w/z8ABz4DHq/5iIEAAAAASUVORK5CYII=", // 紫色
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAAXNSR0IArs4c6QAAAA1JREFUGFdjcHD+/x8ABMsCgoKDrMQAAAAASUVORK5CYII=", // 靛色
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAAXNSR0IArs4c6QAAAA1JREFUGFdjcHj0/z8ABqgDIRlracMAAAAASUVORK5CYII=", // 蓝色
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAAXNSR0IArs4c6QAAAA1JREFUGFdjcPjv9h8ABY0ChShIeUEAAAAASUVORK5CYII=", // 绿色
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAAXNSR0IArs4c6QAAAA1JREFUGFdj+H/I4T8AB8YDAazATdkAAAAASUVORK5CYII=", // 黄色
        ];
    
    // 获取当前时间戳作为随机种子
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    
    // 简单的随机选择
    AVATARS[timestamp as usize % AVATARS.len()]
}

/// 获取用户头像URL
pub fn get_avatar_url_by_id(user_id: Uuid) -> String {
    format!("{}/api/service/profile/{}/avatar", Config::get_global().server.public_url, user_id)
}
