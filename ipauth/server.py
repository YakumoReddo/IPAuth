"""HTTP 服务主模块。

包含鉴权检查、登录、地点管理和绑定查询接口。
"""

from __future__ import annotations

import json
import urllib.parse
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ipauth.config import settings
from ipauth.db import get_conn, init_db, now_ts
from ipauth.policy import evaluate_policy
from ipauth.security import (
    generate_totp_secret,
    hash_password,
    new_session_token,
    token_fingerprint,
    verify_password,
    verify_totp,
)


def _json(handler: BaseHTTPRequestHandler, code: int, payload: dict, headers: dict | None = None) -> None:
    """返回 JSON 响应。"""
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    if headers:
        for k, v in headers.items():
            handler.send_header(k, v)
    handler.end_headers()
    handler.wfile.write(body)


def _empty(handler: BaseHTTPRequestHandler, code: int, headers: dict | None = None) -> None:
    """返回无响应体状态码（例如 204）。"""
    handler.send_response(code)
    if headers:
        for k, v in headers.items():
            handler.send_header(k, v)
    handler.end_headers()


def _parse_json(handler: BaseHTTPRequestHandler) -> dict:
    """解析请求 JSON。空请求体返回空字典。"""
    length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(length) if length > 0 else b"{}"
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


def _client_ip(handler: BaseHTTPRequestHandler) -> str:
    """获取客户端 IP。

    优先读取 X-Forwarded-For 第一段；否则回退到直连地址。
    """
    xff = handler.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return handler.client_address[0]


def _read_cookie_token(handler: BaseHTTPRequestHandler) -> str | None:
    """从 Cookie 中读取会话 Token。"""
    raw = handler.headers.get("Cookie")
    if not raw:
        return None
    c = cookies.SimpleCookie()
    c.load(raw)
    m = c.get(settings.cookie_name)
    return m.value if m else None


def _cookie_header(token: str) -> str:
    """构造 Set-Cookie 响应头。"""
    return (
        f"{settings.cookie_name}={token}; Path=/; HttpOnly; SameSite=Lax; "
        f"Max-Age={settings.cookie_max_age}"
    )


def _lookup_session(conn, token: str):
    """按 token 摘要查询有效会话及其地点属性。"""
    fp = token_fingerprint(token)
    return conn.execute(
        """
        SELECT s.*, l.is_public AS location_public
        FROM sessions s
        LEFT JOIN locations l ON l.id = s.last_location_id
        WHERE s.token_hash = ? AND s.status = 'active'
        """,
        (fp,),
    ).fetchone()


def _get_user_by_username(conn, username: str):
    """按用户名查询用户。"""
    return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def _require_user(handler: BaseHTTPRequestHandler):
    """校验当前请求是否已登录。"""
    token = _read_cookie_token(handler)
    if not token:
        return None, "missing"

    with get_conn(settings.db_path) as conn:
        sess = _lookup_session(conn, token)
        if not sess:
            return None, "invalid"
        if sess["expires_at"] <= now_ts():
            return None, "expired"
        user = conn.execute("SELECT * FROM users WHERE id = ?", (sess["user_id"],)).fetchone()
        if not user:
            return None, "invalid"
        return {"user": user, "session": sess, "token": token}, None


def _create_or_select_location(conn, user_id: int, location_id, location_name: str | None, is_public: bool) -> int | None:
    """选择已有地点或按名称创建新地点。"""
    if location_id is not None:
        row = conn.execute(
            "SELECT id FROM locations WHERE id = ? AND user_id = ?",
            (int(location_id), user_id),
        ).fetchone()
        return int(row["id"]) if row else None

    if location_name:
        cur = conn.execute(
            "INSERT INTO locations(user_id, name, is_public, created_at) VALUES(?,?,?,?)",
            (user_id, location_name, 1 if is_public else 0, now_ts()),
        )
        return int(cur.lastrowid)

    return None


def _upsert_binding(conn, user_id: int, ip: str, location_id: int) -> None:
    """写入或更新用户-IP-地点绑定。"""
    conn.execute(
        """
        INSERT INTO ip_location_bindings(user_id, ip, location_id, last_verified_at)
        VALUES(?,?,?,?)
        ON CONFLICT(user_id, ip)
        DO UPDATE SET location_id = excluded.location_id, last_verified_at = excluded.last_verified_at
        """,
        (user_id, ip, location_id, now_ts()),
    )


def _write_log(conn, user_id, ip: str, location_id, site_id, decision: str, challenge_type, result: str, detail: str):
    """写入认证审计日志。"""
    conn.execute(
        """
        INSERT INTO auth_logs(user_id, ip, location_id, site_id, decision, challenge_type, result, detail, created_at)
        VALUES(?,?,?,?,?,?,?,?,?)
        """,
        (user_id, ip, location_id, site_id, decision, challenge_type, result, detail, now_ts()),
    )


class Handler(BaseHTTPRequestHandler):
    """HTTP 请求处理器。"""

    server_version = "IPAuth/0.1"

    def log_message(self, fmt: str, *args):
        """关闭标准访问日志，避免控制台噪声。"""
        return

    def do_GET(self):
        """处理 GET 路由。"""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/auth/health":
            return _json(self, 200, {"status": "ok"})

        if path == "/auth/check":
            return self._auth_check(parsed.query)

        if path == "/auth/locations":
            return self._list_locations()

        if path == "/auth/bindings":
            return self._list_bindings()

        return _json(self, 404, {"error": "not found"})

    def do_POST(self):
        """处理 POST 路由。"""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/auth/login":
            return self._login()

        if path == "/auth/locations":
            return self._create_location()

        if path == "/auth/admin/users":
            return self._create_user()

        return _json(self, 404, {"error": "not found"})

    def _auth_check(self, query: str):
        """鉴权入口：给 Nginx auth_request 调用。"""
        ip = _client_ip(self)
        site_id = urllib.parse.parse_qs(query).get("site_id", [None])[0]

        token = _read_cookie_token(self)
        cookie_status = "missing"
        sess = None

        with get_conn(settings.db_path) as conn:
            # 先判定 Cookie 状态：缺失/无效/过期/有效。
            if token:
                sess = _lookup_session(conn, token)
                if not sess:
                    cookie_status = "invalid"
                elif sess["expires_at"] <= now_ts():
                    cookie_status = "expired"
                else:
                    cookie_status = "valid"

            same_ip = bool(sess and sess["last_ip"] == ip)
            is_public = bool(sess and sess["location_public"] == 1)
            decision = evaluate_policy(same_ip=same_ip, cookie_status=cookie_status, is_public_location=is_public)

            user_id = sess["user_id"] if sess else None
            location_id = sess["last_location_id"] if sess else None

            if decision.decision == "ALLOW":
                _write_log(
                    conn,
                    user_id,
                    ip,
                    location_id,
                    site_id,
                    decision.decision,
                    decision.challenge_type,
                    "allow",
                    f"cookie_status={cookie_status},same_ip={same_ip},is_public={is_public}",
                )
                return _empty(self, 204)

            _write_log(
                conn,
                user_id,
                ip,
                location_id,
                site_id,
                decision.decision,
                decision.challenge_type,
                "challenge",
                f"cookie_status={cookie_status},same_ip={same_ip},is_public={is_public}",
            )
            return _json(
                self,
                401,
                {
                    "decision": decision.decision,
                    "challenge": decision.challenge_type,
                    "require_location_rebind": decision.require_location_rebind,
                },
            )

    def _login(self):
        """登录接口：根据挑战类型执行 one_of / both 校验并签发会话。"""
        try:
            payload = _parse_json(self)
        except Exception:
            return _json(self, 400, {"error": "invalid json"})

        username = (payload.get("username") or "").strip()
        password = payload.get("password")
        totp_code = payload.get("totp")
        challenge = payload.get("challenge", "both")
        location_id = payload.get("location_id")
        location_name = payload.get("location_name")
        is_public = bool(payload.get("is_public", False))

        if challenge not in {"one_of", "both"}:
            return _json(self, 400, {"error": "challenge must be one_of or both"})

        if not username:
            return _json(self, 400, {"error": "username required"})

        ip = _client_ip(self)

        with get_conn(settings.db_path) as conn:
            user = _get_user_by_username(conn, username)
            if not user:
                return _json(self, 401, {"error": "invalid credentials"})

            pass_ok = bool(password) and verify_password(str(password), user["password_hash"])
            totp_ok = bool(totp_code) and verify_totp(str(totp_code), user["totp_secret"])

            # 两种挑战模式：both 需双因子，one_of 任一通过即可。
            if challenge == "both":
                if not (pass_ok and totp_ok):
                    return _json(self, 401, {"error": "password and totp required"})
            else:
                if not (pass_ok or totp_ok):
                    return _json(self, 401, {"error": "password or totp required"})

            chosen_location_id = _create_or_select_location(
                conn,
                user_id=int(user["id"]),
                location_id=location_id,
                location_name=location_name,
                is_public=is_public,
            )
            if not chosen_location_id:
                return _json(self, 400, {"error": "location_id or location_name required"})

            token = new_session_token()
            now = now_ts()
            expires = now + settings.cookie_max_age
            conn.execute(
                """
                INSERT INTO sessions(user_id, token_hash, issued_at, expires_at, last_ip, last_location_id, status)
                VALUES(?,?,?,?,?,?,?)
                """,
                (
                    int(user["id"]),
                    token_fingerprint(token),
                    now,
                    expires,
                    ip,
                    chosen_location_id,
                    "active",
                ),
            )
            _upsert_binding(conn, int(user["id"]), ip, chosen_location_id)
            _write_log(
                conn,
                int(user["id"]),
                ip,
                chosen_location_id,
                payload.get("site_id"),
                "LOGIN",
                challenge,
                "success",
                "login success",
            )

            return _json(
                self,
                200,
                {
                    "message": "login success",
                    "user_id": int(user["id"]),
                    "location_id": chosen_location_id,
                },
                headers={"Set-Cookie": _cookie_header(token)},
            )

    def _list_locations(self):
        """列出当前用户的地点。"""
        auth, err = _require_user(self)
        if err:
            return _json(self, 401, {"error": "unauthorized", "reason": err})

        with get_conn(settings.db_path) as conn:
            rows = conn.execute(
                "SELECT id, name, is_public, created_at FROM locations WHERE user_id = ? ORDER BY id DESC",
                (int(auth["user"]["id"]),),
            ).fetchall()
            return _json(
                self,
                200,
                {
                    "items": [
                        {
                            "id": int(r["id"]),
                            "name": r["name"],
                            "is_public": bool(r["is_public"]),
                            "created_at": int(r["created_at"]),
                        }
                        for r in rows
                    ]
                },
            )

    def _create_location(self):
        """创建地点。"""
        auth, err = _require_user(self)
        if err:
            return _json(self, 401, {"error": "unauthorized", "reason": err})

        try:
            payload = _parse_json(self)
        except Exception:
            return _json(self, 400, {"error": "invalid json"})

        name = (payload.get("name") or "").strip()
        is_public = bool(payload.get("is_public", False))
        if not name:
            return _json(self, 400, {"error": "name required"})

        with get_conn(settings.db_path) as conn:
            cur = conn.execute(
                "INSERT INTO locations(user_id, name, is_public, created_at) VALUES(?,?,?,?)",
                (int(auth["user"]["id"]), name, 1 if is_public else 0, now_ts()),
            )
            return _json(self, 201, {"id": int(cur.lastrowid), "name": name, "is_public": is_public})

    def _list_bindings(self):
        """查询当前用户的 IP-地点绑定。"""
        auth, err = _require_user(self)
        if err:
            return _json(self, 401, {"error": "unauthorized", "reason": err})

        with get_conn(settings.db_path) as conn:
            rows = conn.execute(
                """
                SELECT b.ip, b.location_id, b.last_verified_at, l.name AS location_name, l.is_public
                FROM ip_location_bindings b
                JOIN locations l ON l.id = b.location_id
                WHERE b.user_id = ?
                ORDER BY b.last_verified_at DESC
                """,
                (int(auth["user"]["id"]),),
            ).fetchall()
            return _json(
                self,
                200,
                {
                    "items": [
                        {
                            "ip": r["ip"],
                            "location_id": int(r["location_id"]),
                            "location_name": r["location_name"],
                            "is_public": bool(r["is_public"]),
                            "last_verified_at": int(r["last_verified_at"]),
                        }
                        for r in rows
                    ]
                },
            )

    def _create_user(self):
        """创建用户（实施阶段便捷接口）。"""
        try:
            payload = _parse_json(self)
        except Exception:
            return _json(self, 400, {"error": "invalid json"})

        username = (payload.get("username") or "").strip()
        password = payload.get("password")
        totp_secret = payload.get("totp_secret") or generate_totp_secret()

        if not username or not password:
            return _json(self, 400, {"error": "username and password required"})

        with get_conn(settings.db_path) as conn:
            try:
                cur = conn.execute(
                    "INSERT INTO users(username, password_hash, totp_secret, created_at) VALUES(?,?,?,?)",
                    (username, hash_password(str(password)), str(totp_secret), now_ts()),
                )
            except Exception:
                return _json(self, 409, {"error": "user exists"})

            return _json(
                self,
                201,
                {
                    "id": int(cur.lastrowid),
                    "username": username,
                    "totp_secret": str(totp_secret),
                },
            )


def run() -> None:
    """初始化数据库并启动 HTTP 服务。"""
    init_db(settings.db_path)
    server = ThreadingHTTPServer((settings.host, settings.port), Handler)
    print(f"IPAuth listening on http://{settings.host}:{settings.port}, db={settings.db_path}")
    server.serve_forever()


if __name__ == "__main__":
    run()
