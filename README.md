# 域名 WHOIS & DNS 查询系统 v2.0

一个高效可用的域名 WHOIS 和 DNS 查询系统，提供美观的可视化网页界面和 RESTful API 接口。

**v2.0 新增：多用户支持、API Key 管理、使用限制、管理面板**

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## ✨ 功能特性

### 核心功能
- 🔍 **WHOIS 查询** - 获取域名注册信息、注册商、过期时间等
- 🔗 **DNS 查询** - 支持 A、AAAA、CNAME、MX、NS、TXT、SOA、CAA 等记录类型
- 📋 **综合查询** - 一次查询获取 WHOIS 和 DNS 全部信息
- 🌍 **广泛支持** - 支持 300+ 顶级域名（gTLD、ccTLD、新 gTLD）
- 🔄 **多层回退** - python-whois → Socket 直连 → IANA → RDAP 四层查询机制

### 用户管理（v2.0）
- 👥 **多用户系统** - 支持管理员和普通用户
- 🔑 **API Key 管理** - 每个用户可创建多个 API Key
- ⏱️ **使用限制** - 可设置每日请求限制和每分钟速率限制
- 📅 **有效期控制** - API Key 可设置过期时间
- 📊 **使用统计** - 实时查看 API 使用量和历史记录
- 🎛️ **管理面板** - 美观的 Web 管理界面

## 🚀 快速开始

### 环境要求

- Python 3.8+
- pip
- 数据库：SQLite（默认，开箱即用）或 MySQL 8.0+

### 1. 克隆项目

```bash
git clone https://github.com/your-username/whoisapi.git
cd whoisapi
```

### 2. 安装依赖

```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
# 或 venv\Scripts\activate  # Windows

pip install -r requirements.txt
```

### 3. 启动服务

**使用 SQLite（默认，无需配置）：**

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

首次启动会自动创建数据库和管理员账户。

### 4. 访问系统

| 页面 | 地址 |
|------|------|
| 🔍 查询页面 | http://localhost:8000 |
| ⚙️ 管理面板 | http://localhost:8000/admin |
| 🧪 API 测试 | http://localhost:8000/test |
| 📚 API 文档 | http://localhost:8000/api/docs |

### 5. 默认账户

| 用户名 | 密码 | 角色 |
|--------|------|------|
| admin | admin | 管理员 |

> ⚠️ **生产环境请务必修改默认密码！**

---

## 📖 使用指南

### 登录管理面板

1. 访问 http://localhost:8000/admin
2. 使用管理员账户登录
3. 在「我的 API Key」页面创建 API Key

### 使用 API

所有查询 API 都需要 API Key 认证：

```bash
# WHOIS 查询
curl -H "X-API-Key: your-api-key" http://localhost:8000/api/whois/google.com

# DNS 查询
curl -H "X-API-Key: your-api-key" http://localhost:8000/api/dns/google.com

# DNS 指定类型
curl -H "X-API-Key: your-api-key" http://localhost:8000/api/dns/google.com/A

# 综合查询
curl -H "X-API-Key: your-api-key" http://localhost:8000/api/lookup/google.com
```

### 使用网页查询

1. 访问 http://localhost:8000
2. 输入域名和 API Key
3. 选择查询类型（综合/WHOIS/DNS）
4. 点击查询

---

## 🔧 配置说明

### 数据库选择

系统支持 **SQLite**（默认）和 **MySQL** 两种数据库：

| 数据库 | 适用场景 | 配置方式 |
|--------|----------|----------|
| SQLite | 开发测试、小型部署 | 无需配置，开箱即用 |
| MySQL | 生产环境、高并发 | 需配置 `.env` 文件 |

### 切换到 MySQL

1. 创建数据库：

```sql
CREATE DATABASE whoisapi CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

2. 创建配置文件：

```bash
cp env.example .env
```

3. 编辑 `.env`：

```env
DATABASE_URL=mysql+aiomysql://root:your_password@localhost:3306/whoisapi
SECRET_KEY=your-random-secret-key-here
ADMIN_PASSWORD=your_secure_password
```

4. 重启服务

### 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| DATABASE_URL | 数据库连接字符串 | sqlite+aiosqlite:///./whoisapi.db |
| SECRET_KEY | JWT 密钥 | your-secret-key... |
| ACCESS_TOKEN_EXPIRE_MINUTES | Token 过期时间 | 30 |
| ADMIN_USERNAME | 管理员用户名 | admin |
| ADMIN_PASSWORD | 管理员密码 | admin |
| ADMIN_EMAIL | 管理员邮箱 | admin@example.com |
| DEFAULT_RATE_LIMIT | 默认每分钟限制 | 100 |
| DEFAULT_DAILY_LIMIT | 默认每日限制 | 1000 |

---

## 🔌 API 接口

### 认证接口

| 方法 | 端点 | 说明 |
|------|------|------|
| POST | `/api/auth/login` | 用户登录 |
| POST | `/api/auth/register` | 用户注册 |
| GET | `/api/auth/me` | 获取当前用户信息 |

### API Key 管理

| 方法 | 端点 | 说明 |
|------|------|------|
| GET | `/api/keys` | 获取我的 API Key 列表 |
| POST | `/api/keys` | 创建新的 API Key |
| PUT | `/api/keys/{id}` | 更新 API Key |
| DELETE | `/api/keys/{id}` | 删除 API Key |

### 查询接口（需要 API Key）

| 方法 | 端点 | 说明 |
|------|------|------|
| GET | `/api/whois/{domain}` | WHOIS 查询 |
| GET | `/api/dns/{domain}` | DNS 查询（所有类型） |
| GET | `/api/dns/{domain}/{type}` | DNS 查询（指定类型） |
| GET | `/api/lookup/{domain}` | 综合查询 |

### 管理接口（需要管理员权限）

| 方法 | 端点 | 说明 |
|------|------|------|
| GET | `/api/admin/users` | 用户列表 |
| POST | `/api/admin/users` | 创建用户 |
| PUT | `/api/admin/users/{id}` | 更新用户 |
| DELETE | `/api/admin/users/{id}` | 删除用户 |
| GET | `/api/admin/api-keys` | 所有 API Key |
| GET | `/api/admin/stats` | 系统统计 |

---

## 📁 项目结构

```
whoisapi/
├── main.py              # FastAPI 主应用（含 WHOIS/DNS 查询逻辑）
├── config.py            # 配置管理
├── database.py          # 数据库连接
├── models.py            # 数据库模型
├── schemas.py           # Pydantic 模型
├── auth.py              # 认证模块
├── routers/
│   ├── auth_router.py   # 认证路由
│   ├── admin_router.py  # 管理路由
│   └── apikey_router.py # API Key 路由
├── static/
│   ├── index.html       # 查询页面
│   ├── admin.html       # 管理面板
│   └── test.html        # API 测试工具
├── requirements.txt     # Python 依赖
├── env.example          # 环境变量示例
└── README.md
```

---

## 🐳 Docker 部署

### Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### docker-compose.yml

```yaml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=mysql+aiomysql://root:password@db:3306/whoisapi
      - SECRET_KEY=your-secret-key-change-this
      - ADMIN_PASSWORD=your-secure-password
    depends_on:
      db:
        condition: service_healthy
    restart: unless-stopped

  db:
    image: mysql:8.0
    environment:
      - MYSQL_ROOT_PASSWORD=password
      - MYSQL_DATABASE=whoisapi
    volumes:
      - mysql_data:/var/lib/mysql
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped

volumes:
  mysql_data:
```

### 运行

```bash
docker-compose up -d
```

---

## 🖥️ 1Panel 部署

### 1. 安装 1Panel

```bash
curl -fsSL https://1panel.cn/install.sh | bash
```

### 2. Docker Compose 部署

1. 打开 1Panel 控制台 →「应用商店」→「自定义部署」→「Docker Compose」
2. 粘贴上面的 `docker-compose.yml` 内容
3. 上传项目文件到指定目录
4. 部署应用

### 3. 配置域名（可选）

- 在 1Panel「网站」中创建反向代理，指向 `127.0.0.1:8000`
- 申请或上传 HTTPS 证书

---

## 🌐 支持的域名类型

| 类别 | 示例 | 数量 |
|------|------|------|
| 传统通用域名 | .com, .net, .org | ~15 |
| 新通用顶级域名 | .xyz, .top, .dev, .app | 120+ |
| 欧洲国家域名 | .uk, .de, .fr, .eu | ~35 |
| 亚洲国家域名 | .cn, .jp, .kr, .hk | ~20 |
| 其他国家域名 | .au, .br, .za | 60+ |
| 二级国家域名 | .co.uk, .com.cn | ~40 |

---

## ⚠️ 注意事项

1. **安全配置**：生产环境务必修改 `SECRET_KEY` 和管理员密码
2. **WHOIS 限制**：部分注册商对 WHOIS 查询有频率限制，请合理使用
3. **隐私保护**：由于 GDPR 等法规，部分域名的 WHOIS 信息可能被隐藏
4. **数据备份**：生产环境建议定期备份数据库
5. **API Key 安全**：请妥善保管 API Key，不要泄露到公开代码中

---

## 📄 许可证

MIT License

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！
