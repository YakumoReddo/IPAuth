# IPAuth (Python + SQLite)

## 运行环境
- Python 3.11+

## 启动
```powershell
cd g:\workspace\ipauth
python .\main.py
```

默认监听：`127.0.0.1:8080`，默认数据库：`./ipauth.db`

可选环境变量：
- `IPAUTH_DB_PATH`
- `IPAUTH_HOST`
- `IPAUTH_PORT`
- `IPAUTH_COOKIE_NAME`
- `IPAUTH_COOKIE_MAX_AGE`

## 初始化用户
```powershell
curl -X POST http://127.0.0.1:8080/auth/admin/users ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"alice\",\"password\":\"Passw0rd!\"}"
```
返回里会包含 `totp_secret`。

## 核心接口
- `GET /auth/health`
- `GET /auth/login`（内置登录页）
- `GET /auth/check`
- `POST /auth/login`
- `GET /auth/locations`
- `POST /auth/locations`
- `GET /auth/bindings`

## 登录示例
```powershell
curl -i -X POST http://127.0.0.1:8080/auth/login ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"alice\",\"password\":\"Passw0rd!\",\"totp\":\"123456\",\"challenge\":\"both\",\"location_name\":\"home\",\"is_public\":false}"
```

## Nginx 对接（示意）
- 让 `auth_request` 指向 `GET /auth/check`
- 返回 `204` 则放行，`401` 则要求登录
