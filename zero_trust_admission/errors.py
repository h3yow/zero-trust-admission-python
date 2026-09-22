"""策略装载阶段的可区分错误类型。"""

from __future__ import annotations


class PolicyError(Exception):
    """策略相关错误基类。"""

    code = "policy_error"


class PolicyFormatError(PolicyError):
    """策略内容不是合法的声明式结构（JSON 解析失败/字段缺失/字段类型错误）。"""

    code = "policy_format_error"


class PolicySchemaVersionError(PolicyError):
    """策略 schema 版本不受支持或不兼容。"""

    code = "policy_version_incompatible"


class PolicyConflictError(PolicyError):
    """新策略与既有规则冲突（同一优先级下 allow/deny 同时命中）。"""

    code = "policy_conflict"


class PolicyValidationError(PolicyError):
    """策略语义非法（取值越界、限流窗口缺失等）。"""

    code = "policy_validation_error"


class AuditUnavailableError(Exception):
    """审计后端不可用。"""

    code = "audit_unavailable"
