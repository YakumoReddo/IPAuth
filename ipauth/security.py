"""安全相关工具。

包含密码哈希校验、TOTP、会话令牌生成与摘要。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time


def _b64(data: bytes) -> str:
    """URL 安全 Base64 编码（去掉尾部填充）。"""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64_decode(data: str) -> bytes:
    """URL 安全 Base64 解码（自动补齐填充）。"""
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("ascii"))


def hash_password(password: str, iterations: int = 200_000) -> str:
    """使用 PBKDF2-HMAC-SHA256 生成密码哈希串。"""
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, encoded: str) -> bool:
    """校验明文密码与存储哈希是否匹配。"""
    try:
        algo, iter_s, salt_s, digest_s = encoded.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iter_s)
        salt = _b64_decode(salt_s)
        expected = _b64_decode(digest_s)
    except Exception:
        return False

    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(actual, expected)


def generate_totp_secret() -> str:
    """生成 Base32 TOTP 密钥。"""
    return base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")


def _totp(secret: str, for_time: int, step: int = 30, digits: int = 6) -> str:
    """按 RFC 6238 计算某一时刻的 TOTP。"""
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    counter = int(for_time // step)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10**digits)).zfill(digits)


def verify_totp(code: str, secret: str, skew: int = 1) -> bool:
    """校验 TOTP，支持时间窗口偏移（默认 ±1 个步长）。"""
    if not code or not code.isdigit():
        return False
    now = int(time.time())
    for i in range(-skew, skew + 1):
        if hmac.compare_digest(code, _totp(secret, now + i * 30)):
            return True
    return False


def new_session_token() -> str:
    """生成随机会话令牌。"""
    return _b64(os.urandom(32))


def token_fingerprint(token: str) -> str:
    """计算令牌摘要，避免在数据库明文保存 token。"""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
