"""认证策略引擎。

根据 IP/Cookie/地点属性输出挑战强度。
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PolicyDecision:
    """策略输出结果。"""

    decision: str
    challenge_type: str | None
    require_location_rebind: bool = False


def evaluate_policy(same_ip: bool, cookie_status: str, is_public_location: bool) -> PolicyDecision:
    """执行策略决策。

    规则来源于项目说明：
    - 同 IP + Cookie 有效：直接放行
    - 同 IP + Cookie 过期：公共地点二选一，其他放行
    - 同 IP + Cookie 缺失/无效：二选一
    - 异 IP + Cookie 有效：二选一 + 重选地点
    - 其他异 IP：双因子
    """
    if same_ip and cookie_status == "valid":
        return PolicyDecision("ALLOW", None, False)

    if same_ip and cookie_status == "expired":
        if is_public_location:
            return PolicyDecision("CHALLENGE", "one_of", False)
        return PolicyDecision("ALLOW", None, False)

    if same_ip and cookie_status in {"missing", "invalid"}:
        return PolicyDecision("CHALLENGE", "one_of", False)

    if (not same_ip) and cookie_status == "valid":
        return PolicyDecision("CHALLENGE", "one_of", True)

    return PolicyDecision("CHALLENGE", "both", False)
