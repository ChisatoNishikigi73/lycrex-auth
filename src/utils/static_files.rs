use actix_web::{HttpResponse, Result};
use std::collections::HashMap;
use std::sync::OnceLock;
use std::fs;
use std::path::Path;
use log::warn;

// 静态文件存储
static STATIC_FILES: OnceLock<HashMap<String, Vec<u8>>> = OnceLock::new();

// 扫描静态文件目录并加载所有文件
fn scan_static_dir(base_dir: &str) -> HashMap<String, Vec<u8>> {
    let mut files = HashMap::new();
    
    // 手动添加CSS文件
    match include_bytes!("../../static/css/main.css") {
        content => {
            files.insert("css/main.css".to_string(), content.to_vec());
            println!("已加载静态文件: css/main.css");
        }
    }
    
    // 手动添加字体文件
    match include_bytes!("../../static/fonts/JetBrainsMono-Light.woff2") {
        content => {
            files.insert("fonts/JetBrainsMono-Light.woff2".to_string(), content.to_vec());
            println!("已加载静态文件: fonts/JetBrainsMono-Light.woff2");
        }
    }
    
    match include_bytes!("../../static/fonts/JetBrainsMono-Regular.woff2") {
        content => {
            files.insert("fonts/JetBrainsMono-Regular.woff2".to_string(), content.to_vec());
            println!("已加载静态文件: fonts/JetBrainsMono-Regular.woff2");
        }
    }
    
    match include_bytes!("../../static/fonts/JetBrainsMono-Medium.woff2") {
        content => {
            files.insert("fonts/JetBrainsMono-Medium.woff2".to_string(), content.to_vec());
            println!("已加载静态文件: fonts/JetBrainsMono-Medium.woff2");
        }
    }
    
    match include_bytes!("../../static/fonts/JetBrainsMono-Bold.woff2") {
        content => {
            files.insert("fonts/JetBrainsMono-Bold.woff2".to_string(), content.to_vec());
            println!("已加载静态文件: fonts/JetBrainsMono-Bold.woff2");
        }
    }
    
    match include_bytes!("../../static/fonts/JetBrainsMono-ExtraLight.woff2") {
        content => {
            files.insert("fonts/JetBrainsMono-ExtraLight.woff2".to_string(), content.to_vec());
            println!("已加载静态文件: fonts/JetBrainsMono-ExtraLight.woff2");
        }
    }
    
    // 如果在运行时存在静态目录，也从目录中加载文件
    if let Ok(entries) = fs::read_dir(base_dir) {
        for entry in entries.flatten() {
            if let Ok(file_type) = entry.file_type() {
                let path = entry.path();
                
                if file_type.is_file() {
                    if let Some(file_name) = path.file_name() {
                        if file_name.to_str().is_some() {
                            if let Ok(content) = fs::read(&path) {
                                let rel_path = path.strip_prefix(base_dir).unwrap_or(&path);
                                if let Some(rel_path_str) = rel_path.to_str() {
                                    files.insert(rel_path_str.to_string(), content);
                                    println!("从目录加载静态文件: {}", rel_path_str);
                                }
                            }
                        }
                    }
                } else if file_type.is_dir() {
                    // 递归处理子目录
                    let subdir_path = path.to_str().unwrap_or_default();
                    let subfiles = scan_static_dir(subdir_path);
                    for (subpath, content) in subfiles {
                        let rel_path = Path::new(subdir_path).join(subpath);
                        if let Some(rel_path_str) = rel_path.strip_prefix(base_dir)
                            .ok()
                            .and_then(|p| p.to_str()) {
                            files.insert(rel_path_str.to_string(), content);
                            println!("从子目录加载静态文件: {}", rel_path_str);
                        }
                    }
                }
            }
        }
    }
    
    println!("总共加载了 {} 个静态文件", files.len());
    files
}

// 初始化静态文件
fn get_static_files() -> &'static HashMap<String, Vec<u8>> {
    STATIC_FILES.get_or_init(|| {
        // 尝试扫描静态目录
        scan_static_dir("static")
    })
}

// 创建一个处理静态文件请求的函数
pub async fn serve_static_file(path: String) -> Result<HttpResponse> {
    // 移除开头的斜杠
    let path = path.trim_start_matches('/');
    
    // 如果路径为空，返回404
    if path.is_empty() {
        return Ok(HttpResponse::NotFound().body("文件不存在"));
    }
    
    // 获取静态文件集合
    let files = get_static_files();
    
    // 尝试获取文件
    match files.get(path) {
        Some(content) => {
            // 猜测MIME类型
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            
            // 构建响应
            let mut response = HttpResponse::Ok();
            response.content_type(mime.as_ref());
            
            // 返回响应
            Ok(response.body(content.clone()))
        },
        None => {
            warn!("静态文件不存在: {}", path);
            Ok(HttpResponse::NotFound().body(format!("文件不存在: {}", path)))
        }
    }
} 