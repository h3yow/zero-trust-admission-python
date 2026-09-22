"""兼容旧入口：FastAPI 应用从包内装配层导入。"""

from zero_trust_admission.app import app

__all__ = ["app"]
