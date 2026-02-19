# WHOIS API

域名 WHOIS 和 DNS 查询系统，提供 Web 界面和 RESTful API。

## 功能

- 🔍 WHOIS 查询 — 域名注册信息
- 🌐 DNS 查询 — A/AAAA/MX/NS/TXT/CNAME 等记录
- 📊 综合查询 — WHOIS + DNS 一键查询
- 👥 多用户支持 — 注册、登录、API Key 管理
- 🔑 灵活的 API Key 策略 — 网页查询可设置为免 Key 或需要 Key
- 📈 用量统计 — 每日请求数限制和统计
- 🛡️ 管理面板 — 用户管理、设置管理

## 快速开始（Docker）

```bash
# 1. 克隆项目
git clone https://github.com/rikouu/whoisapi.git
cd whoisapi

# 2. 配置环境变量
cp env.example .env
# 编辑 .env，修改密码和密钥

# 3. 启动
docker compose up -d

# 4. 访问
# Web 界面：http://localhost:8900
# 管理面板：http://localhost:8900/admin
# API 文档：http://localhost:8900/docs
```

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `DATABASE_URL` | `sqlite+aiosqlite:///./data/whoisapi.db` | 数据库连接 |
| `SECRET_KEY` | — | JWT 签名密钥（必须修改） |
| `ADMIN_USERNAME` | `admin` | 管理员用户名 |
| `ADMIN_PASSWORD` | `admin` | 管理员密码 |
| `ADMIN_EMAIL` | `admin@example.com` | 管理员邮箱 |
| `DEFAULT_RATE_LIMIT` | `100` | 每分钟请求限制 |
| `DEFAULT_DAILY_LIMIT` | `1000` | 每日请求限制 |
| `WEB_QUERY_REQUIRE_API_KEY` | `false` | 网页查询是否需要 API Key |
| `PORT` | `8900` | 主机映射端口 |
| `TZ` | `Asia/Tokyo` | 时区 |

## API 使用

```bash
# WHOIS 查询
curl -H "X-API-Key: your-key" https://your-domain/api/whois/example.com

# DNS 查询
curl -H "X-API-Key: your-key" https://your-domain/api/dns/example.com

# 综合查询
curl -H "X-API-Key: your-key" https://your-domain/api/lookup/example.com
```

如果 `WEB_QUERY_REQUIRE_API_KEY=false`，网页端可直接查询无需 API Key；API 调用仍建议使用 Key 以获取更高配额。

## 本地开发

```bash
pip install -r requirements.txt
cp env.example .env
uvicorn main:app --reload --port 8000
```

## License

MIT
