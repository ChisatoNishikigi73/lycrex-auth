use actix_web::{web, HttpResponse, Responder};
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;
use crate::services::user as user_service;

#[derive(Deserialize)]
pub struct LoginQuery {
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub response_type: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
}

// 登录页面
pub async fn login_page(
    query: web::Query<LoginQuery>,
    session: actix_session::Session,
) -> impl Responder {
    // 检查当前会话
    let login_status = match session.get::<String>("user_id") {
        Ok(Some(user_id)) => {
            log::info!("用户已登录，用户ID: {}", user_id);
            format!("用户 {} 已登录", user_id)
        },
        _ => {
            log::info!("用户未登录，显示登录页面");
            "未登录".to_string()
        }
    };
    
    // 设置默认值
    let client_id = query.client_id.as_deref().unwrap_or("test_client");
    let redirect_uri = query.redirect_uri.as_deref().unwrap_or("http://localhost:3000/callback");
    let response_type = query.response_type.as_deref().unwrap_or("code");
    let scope = query.scope.as_deref().unwrap_or("");
    let state = query.state.as_deref().unwrap_or("");
    
    let html = format!(
        r#"
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Lycrex 认证 - 登录</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
                .container {{ max-width: 400px; margin: 50px auto; padding: 20px; background-color: white; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                h1 {{ color: #333; text-align: center; }}
                label {{ display: block; margin: 10px 0 5px; color: #555; }}
                input {{ width: 100%; padding: 8px; margin-bottom: 15px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }}
                button {{ width: 100%; padding: 10px; background-color: #4CAF50; color: white; border: none; border-radius: 4px; cursor: pointer; }}
                button:hover {{ background-color: #45a049; }}
                .error {{ color: red; margin-bottom: 15px; }}
                .status {{ color: blue; margin-bottom: 15px; text-align: center; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Lycrex 认证</h1>
                <div class="status">{}</div>
                <div id="error" class="error" style="display: none;"></div>
                <form id="loginForm">
                    <label for="email">电子邮箱</label>
                    <input type="email" id="email" name="email" required>
                    
                    <label for="password">密码</label>
                    <input type="password" id="password" name="password" required>
                    
                    <input type="hidden" name="client_id" value="{}">
                    <input type="hidden" name="redirect_uri" value="{}">
                    <input type="hidden" name="response_type" value="{}">
                    <input type="hidden" name="scope" value="{}">
                    <input type="hidden" name="state" value="{}">
                    
                    <button type="submit">登录</button>
                </form>
                <p style="text-align: center; margin-top: 20px;">
                    没有账号？<a href="/register">注册</a>
                </p>
            </div>
            
            <script>
                document.getElementById('loginForm').addEventListener('submit', async function(e) {{
                    e.preventDefault();
                    
                    const email = document.getElementById('email').value;
                    const password = document.getElementById('password').value;
                    
                    try {{
                        // 发送登录请求
                        const response = await fetch('/api/auth/login', {{
                            method: 'POST',
                            headers: {{
                                'Content-Type': 'application/json'
                            }},
                            body: JSON.stringify({{ email, password }}),
                            credentials: 'include' // 确保包含cookie
                        }});
                        
                        if (response.ok) {{
                            // 获取表单中可能存在的隐藏字段值
                            const formElements = document.getElementById('loginForm').elements;
                            let clientId = '';
                            let redirectUri = '';
                            let responseType = '';
                            let scope = '';
                            let state = '';
                            
                            // 安全地获取表单字段值
                            if(formElements.namedItem('client_id')) clientId = formElements.namedItem('client_id').value;
                            if(formElements.namedItem('redirect_uri')) redirectUri = formElements.namedItem('redirect_uri').value;
                            if(formElements.namedItem('response_type')) responseType = formElements.namedItem('response_type').value;
                            if(formElements.namedItem('scope')) scope = formElements.namedItem('scope').value;
                            if(formElements.namedItem('state')) state = formElements.namedItem('state').value;
                            
                            // 使用同步提交表单方式重定向，确保cookie能被正确处理
                            if (clientId && redirectUri && responseType) {{
                                const form = document.createElement('form');
                                form.method = 'GET';
                                form.action = '/api/oauth/authorize';
                                
                                // 添加隐藏字段
                                function addField(name, value) {{
                                    const input = document.createElement('input');
                                    input.type = 'hidden';
                                    input.name = name;
                                    input.value = value;
                                    form.appendChild(input);
                                }}
                                
                                addField('client_id', clientId);
                                addField('redirect_uri', redirectUri);
                                addField('response_type', responseType);
                                if (scope) addField('scope', scope);
                                if (state) addField('state', state);
                                
                                // 添加从响应中获取的用户ID
                                try {{
                                    const userData = await response.json();
                                    if (userData && userData.id) {{
                                        addField('user_id', userData.id);
                                        console.log('添加用户ID到请求: ', userData.id);
                                    }}
                                }} catch(e) {{
                                    console.error('无法解析用户数据', e);
                                }}
                                
                                // 添加到文档并提交
                                document.body.appendChild(form);
                                form.submit();
                            }} else {{
                                window.location.href = '/';
                            }}
                        }} else {{
                            const error = await response.text();
                            document.getElementById('error').textContent = `登录失败: ${{error}}`;
                            document.getElementById('error').style.display = 'block';
                        }}
                    }} catch (error) {{
                        document.getElementById('error').textContent = `请求错误: ${{error.message}}`;
                        document.getElementById('error').style.display = 'block';
                    }}
                }});
            </script>
        </body>
        </html>
        "#,
        login_status,
        client_id,
        redirect_uri,
        response_type,
        scope,
        state
    );
    
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

// 注册页面
pub async fn register_page() -> impl Responder {
    let html = r#"
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Lycrex 认证 - 注册</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
            .container { max-width: 400px; margin: 50px auto; padding: 20px; background-color: white; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #333; text-align: center; }
            label { display: block; margin: 10px 0 5px; color: #555; }
            input { width: 100%; padding: 8px; margin-bottom: 15px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
            button { width: 100%; padding: 10px; background-color: #4CAF50; color: white; border: none; border-radius: 4px; cursor: pointer; }
            button:hover { background-color: #45a049; }
            .error { color: red; margin-bottom: 15px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>创建账号</h1>
            <div id="error" class="error" style="display: none;"></div>
            <form id="registerForm">
                <label for="username">用户名</label>
                <input type="text" id="username" name="username" required>
                
                <label for="email">电子邮箱</label>
                <input type="email" id="email" name="email" required>
                
                <label for="password">密码</label>
                <input type="password" id="password" name="password" required minlength="6">
                
                <button type="submit">注册</button>
            </form>
            <p style="text-align: center; margin-top: 20px;">
                已有账号？<a href="/login">登录</a>
            </p>
        </div>
        
        <script>
            document.getElementById('registerForm').addEventListener('submit', async function(e) {
                e.preventDefault();
                
                const username = document.getElementById('username').value;
                const email = document.getElementById('email').value;
                const password = document.getElementById('password').value;
                
                try {
                    // 发送注册请求
                    const response = await fetch('/api/auth/register', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ username, email, password })
                    });
                    
                    if (response.ok) {
                        // 注册成功，重定向到登录页面
                        window.location.href = '/login';
                    } else {
                        const error = await response.text();
                        document.getElementById('error').textContent = `注册失败: ${error}`;
                        document.getElementById('error').style.display = 'block';
                    }
                } catch (error) {
                    document.getElementById('error').textContent = `请求错误: ${error.message}`;
                    document.getElementById('error').style.display = 'block';
                }
            });
        </script>
    </body>
    </html>
    "#;
    
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

// 首页
pub async fn index_page(session: actix_session::Session) -> impl Responder {
    // 检查用户是否已登录
    let user_id = session.get::<String>("user_id").ok().flatten();
    
    let html = match user_id {
        Some(user_id_str) => {
            // 用户已登录
            format!(
                r#"
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>Lycrex 认证 - 首页</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
                        .container {{ max-width: 800px; margin: 50px auto; padding: 20px; background-color: white; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                        h1 {{ color: #333; text-align: center; }}
                        p {{ line-height: 1.6; }}
                        .button {{ display: inline-block; padding: 10px 15px; margin: 10px 5px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 4px; }}
                        .button.red {{ background-color: #f44336; }}
                        .button:hover {{ opacity: 0.9; }}
                        .text-center {{ text-align: center; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>Lycrex 认证系统</h1>
                        <p>您已登录系统，用户ID: {}</p>
                        <div class="text-center">
                            <a href="/profile" class="button">个人信息</a>
                            <form action="/api/auth/logout" method="post" style="display: inline;">
                                <button type="submit" class="button red">退出登录</button>
                            </form>
                        </div>
                    </div>
                </body>
                </html>
                "#,
                user_id_str
            )
        },
        None => {
            // 用户未登录
            r#"
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Lycrex 认证 - 首页</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
                    .container { max-width: 800px; margin: 50px auto; padding: 20px; background-color: white; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                    h1 { color: #333; text-align: center; }
                    p { line-height: 1.6; }
                    .button { display: inline-block; padding: 10px 15px; margin: 10px 5px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 4px; }
                    .button:hover { opacity: 0.9; }
                    .text-center { text-align: center; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Lycrex 认证系统</h1>
                    <p>欢迎使用Lycrex认证系统，请选择以下操作：</p>
                    <div class="text-center">
                        <a href="/login" class="button">登录</a>
                        <a href="/register" class="button">注册</a>
                    </div>
                </div>
            </body>
            </html>
            "#.to_string()
        }
    };
    
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

// 用户个人页面
pub async fn profile_page(
    session: actix_session::Session,
    db: web::Data<PgPool>,
) -> impl Responder {
    // 检查用户是否已登录
    let user_id = match session.get::<String>("user_id").ok().flatten() {
        Some(id) => id,
        None => {
            // 未登录，重定向到首页
            return HttpResponse::Found()
                .append_header(("Location", "/"))
                .finish();
        }
    };
    
    // 获取用户信息
    let user_uuid = match Uuid::parse_str(&user_id) {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::Found()
                .append_header(("Location", "/"))
                .finish();
        }
    };
    
    let user = match user_service::get_user_by_id(user_uuid, &db).await {
        Ok(user) => user,
        Err(_) => {
            return HttpResponse::Found()
                .append_header(("Location", "/"))
                .finish();
        }
    };
    
    // 生成页面
    let html = format!(
        r#"
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Lycrex 认证 - 个人信息</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
                .container {{ max-width: 800px; margin: 50px auto; padding: 20px; background-color: white; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                h1 {{ color: #333; text-align: center; }}
                p {{ line-height: 1.6; }}
                .user-info {{ background-color: #f9f9f9; padding: 15px; border-radius: 4px; margin: 20px 0; }}
                .button {{ display: inline-block; padding: 10px 15px; margin: 10px 5px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 4px; }}
                .button.red {{ background-color: #f44336; }}
                .button:hover {{ opacity: 0.9; }}
                .text-center {{ text-align: center; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>用户个人信息</h1>
                
                <div class="user-info">
                    <p><strong>用户ID:</strong> {}</p>
                    <p><strong>用户名:</strong> {}</p>
                    <p><strong>电子邮箱:</strong> {}</p>
                    <p><strong>注册时间:</strong> {}</p>
                </div>
                
                <div class="text-center">
                    <a href="/" class="button">返回首页</a>
                    <form action="/api/auth/logout" method="post" style="display: inline;">
                        <button type="submit" class="button red">退出登录</button>
                    </form>
                </div>
            </div>
        </body>
        </html>
        "#,
        user.id,
        user.username,
        user.email,
        user.created_at.format("%Y-%m-%d %H:%M:%S")
    );
    
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
} 