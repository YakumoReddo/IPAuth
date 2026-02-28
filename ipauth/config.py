"""运行时配置。

通过环境变量覆盖默认值，便于本地与生产环境切换。
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    """应用配置项。"""

    # SQLite 数据库文件路径。
    db_path: str = os.environ.get("IPAUTH_DB_PATH", "./ipauth.db")
    # 服务监听地址。
    host: str = os.environ.get("IPAUTH_HOST", "127.0.0.1")
    # 服务监听端口。
    port: int = int(os.environ.get("IPAUTH_PORT", "8080"))
    # 会话 Cookie 名称。
    cookie_name: str = os.environ.get("IPAUTH_COOKIE_NAME", "ipauth_token")
    # 会话 Cookie 有效期（秒）。
    cookie_max_age: int = int(os.environ.get("IPAUTH_COOKIE_MAX_AGE", str(7 * 24 * 3600)))


# 全局配置实例。
settings = Settings()
