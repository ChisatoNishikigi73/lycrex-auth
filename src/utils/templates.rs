use std::fmt;

/// 登录页面HTML模板
pub static LOGIN_PAGE: &str = include_str!("../templates/login.html");

/// 注册页面HTML模板
pub static REGISTER_PAGE: &str = include_str!("../templates/register.html");

/// 欢迎页面HTML模板
pub static WELCOME_PAGE: &str = include_str!("../templates/welcome.html");

/// 警告页面HTML模板
pub static WARNING_PAGE: &str = include_str!("../templates/warning.html");

/// API文档页面HTML模板
pub static API_DOCS_PAGE: &str = include_str!("../templates/api_docs.html");


/// ---管理员---

/// 管理员页面HTML模板
pub static ADMIN_PAGE: &str = include_str!("../templates/admin/admin.html");

/// 管理员登录页面HTML模板
pub static ADMIN_LOGIN_PAGE: &str = include_str!("../templates/admin/admin_login.html");

/// 管理员用户管理页面HTML模板
pub static ADMIN_USERS_PAGE: &str = include_str!("../templates/admin/admin_users.html");

/// 格式化模板字符串，使用给定参数替换{}占位符
pub fn format_template(template: &str, args: &[&dyn fmt::Display]) -> String {
    let mut result = template.to_string();
    let mut search_from = 0;
    
    for arg in args {
        if let Some(pos) = result[search_from..].find("{}") {
            let replace_pos = search_from + pos;
            let replacement = format!("{}", arg);
            result.replace_range(replace_pos..replace_pos + 2, &replacement);
            search_from = replace_pos + replacement.len();
        } else {
            break;
        }
    }
    
    result
}

/// 渲染登录页面
pub fn render_login(status: &str, client_id: &str, redirect_uri: &str, 
                   response_type: &str, scope: &str, state: &str) -> String {
    format_template(LOGIN_PAGE, &[&status, &client_id, &redirect_uri, 
                                  &response_type, &scope, &state])
}

/// 渲染警告页面
pub fn render_warning(message: &str) -> String {
    format_template(WARNING_PAGE, &[&message])
}

/// 渲染欢迎页面
pub fn render_welcome(username: &str, redirect_url: &str) -> String {
    format_template(WELCOME_PAGE, &[&username, &redirect_url])
} 