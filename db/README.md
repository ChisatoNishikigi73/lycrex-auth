# 数据库管理

本项目使用PostgreSQL数据库和SQLx库进行数据库操作。

## 目录结构

- `db/scripts/` - SQL脚本和数据库工具
  - `init-db.sql` - 手动数据库初始化SQL（如果需要）
  - `local/` - 本地环境特定的数据库脚本（不提交到版本控制）
- `migrations/` - SQLx迁移文件
- `.sqlx/` - SQLx临时文件
- `sqlx-data.json` - SQLx查询元数据（用于离线编译）

## 数据库迁移

项目使用SQLx内置的迁移系统。迁移文件位于`migrations/`目录，采用以下命名格式：

```sql
{timestamp}_{description}.sql
```

例如：`20230501000000_create_initial_tables.sql`

迁移将自动按文件名顺序执行。每个迁移文件应该是幂等的，意味着它可以多次运行而不会产生副作用。

### 创建新的迁移

```bash
# 手动创建迁移文件
# 格式：YYYYMMDDHHMMSS_description.sql
touch migrations/$(date +%Y%m%d%H%M%S)_my_migration.sql

# 或使用SQLx CLI（如已安装）
cargo install sqlx-cli
sqlx migrate add my_migration
```

## SQLx离线模式

SQLx离线模式允许在没有数据库连接的情况下编译项目，这对CI/CD环境特别有用。

### 关于sqlx-data.json

`sqlx-data.json`文件包含项目中所有SQL查询的元数据，使得SQLx可以在没有数据库连接的情况下执行类型检查。这个文件**不是必需的**，但有以下好处：

1. 在没有数据库的环境中编译（CI/CD、Docker构建等）
2. 加快编译速度
3. 确保所有查询在编译时有效

### 管理sqlx-data.json

**更新查询元数据**:

```bash
# 确保数据库可用
cargo sqlx prepare --check
```

**使用离线模式**:

```bash
# 启用离线模式
export SQLX_OFFLINE=true

# 编译项目
cargo build
```

**完全禁用离线模式**:

如果不需要离线模式，可以:

1. 删除`sqlx-data.json`文件
2. 在`.gitignore`中添加`sqlx-data.json`
3. 确保所有编译环境都有可用的数据库连接

## 数据库初始化

项目使用多种方式初始化数据库：

1. **自动初始化** - 通过代码中的`db::init_database_tables`函数自动创建表
2. **迁移** - 通过`migrations/`目录中的SQL文件进行版本化迁移
3. **手动初始化** - 如果需要，可以使用`db/scripts/init-db.sql`手动初始化数据库
