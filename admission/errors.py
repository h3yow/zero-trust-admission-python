"""可区分的错误原因码与异常类型。"""

from __future__ import annotations


class AdmissionError(Exception):
    """准入相关错误的基类，携带可区分的机器可读原因码。"""

    reason_code = "ADMISSION_ERROR"

    def __init__(self, reason: str = "") -> None:
        super().__init__(reason or self.reason_code)
        self.reason = reason or self.reason_code


class PolicyValidationError(AdmissionError):
    reason_code = "POLICY_INVALID"


class PolicyVersionError(AdmissionError):
    reason_code = "POLICY_VERSION_INCOMPATIBLE"


class PolicyConflictError(AdmissionError):
    reason_code = "POLICY_CONFLICT"


class PolicyNotFoundError(AdmissionError):
    reason_code = "POLICY_NOT_FOUND"


class DenyError(AdmissionError):
    """判定拒绝基类：默认拒绝 / 显式拒绝。"""

    reason_code = "DENIED"


class DefaultDenyError(DenyError):
    reason_code = "DENY_NO_MATCHING_RULE"


class ExplicitDenyError(DenyError):
    reason_code = "DENY_EXPLICIT_RULE"


class RateLimitedError(DenyError):
    reason_code = "RATE_LIMIT_EXCEEDED"

    def __init__(
        self, reason: str, *, rule_id: str = "", limit: int = 0, window: float = 0.0
    ) -> None:
        super().__init__(reason)
        self.rule_id = rule_id
        self.limit = limit
        self.window = window


class ConcurrencyLimitError(DenyError):
    reason_code = "CONCURRENCY_LIMIT_EXCEEDED"

    def __init__(self, reason: str, *, rule_id: str = "", limit: int = 0) -> None:
        super().__init__(reason)
        self.rule_id = rule_id
        self.limit = limit


class AuditUnavailableError(AdmissionError):
    reason_code = "AUDIT_UNAVAILABLE"


class DownstreamError(AdmissionError):
    reason_code = "DOWNSTREAM_ERROR"
