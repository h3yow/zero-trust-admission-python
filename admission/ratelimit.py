"""按 身份×资源×动作×规则 维度隔离的固定窗口限流与并发约束。

关键性质：
- 所有配额操作都在同一把锁内完成“检查+占用”，突发/重复请求下计数不漂移；
- 计数器以完整复合键索引，多身份混合访问绝不串号；
- 未超限流量永远放行（新窗口重置计数，不误伤）；
- release 仅在当前窗口且计数 >0 时扣减，回滚不会造成负数漂移；
- 过期窗口在每次操作时惰性清理，字典不会随键数量无界增长。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

# 键数超过该阈值时，在持锁操作内顺带清理过期窗口
_PURGE_THRESHOLD = 1024


@dataclass
class _Window:
    window_start: float = 0.0
    count: int = 0
    window_seconds: float = 0.0


@dataclass
class RateLimiter:
    """固定窗口计数器；键隔离保证不跨身份串号。"""

    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _windows: dict[tuple[Any, ...], _Window] = field(default_factory=dict)

    def _purge_expired_locked(self, now: float) -> None:
        if len(self._windows) < _PURGE_THRESHOLD:
            return
        expired = [
            k
            for k, w in self._windows.items()
            if (now - w.window_start) >= w.window_seconds
        ]
        for k in expired:
            del self._windows[k]

    def try_acquire(
        self,
        key: tuple[Any, ...],
        max_requests: int,
        window_seconds: float,
        now: float,
    ) -> bool:
        """原子地检查并占用一个配额，成功返回 True，超限返回 False。"""
        with self._lock:
            self._purge_expired_locked(now)
            win = self._windows.get(key)
            if win is None or (now - win.window_start) >= window_seconds:
                win = _Window(window_start=now, count=0, window_seconds=window_seconds)
                self._windows[key] = win
            if win.count >= max_requests:
                return False
            win.count += 1
            return True

    def release(
        self,
        key: tuple[Any, ...],
        max_requests: int,
        window_seconds: float,
        now: float,
    ) -> None:
        """归还一个配额（审计写入失败等回滚场景）。不会跨窗口回滚、不会变负。"""
        with self._lock:
            win = self._windows.get(key)
            if win is None or (now - win.window_start) >= win.window_seconds:
                return
            if win.count > 0:
                win.count -= 1

    def current_count(self, key: tuple[Any, ...]) -> int:
        with self._lock:
            win = self._windows.get(key)
            return win.count if win is not None else 0

    def size(self) -> int:
        with self._lock:
            return len(self._windows)

    def reset(self) -> None:
        with self._lock:
            self._windows.clear()


@dataclass
class ConcurrencyLimiter:
    """每键独立 BoundedSemaphore，键之间互不影响。"""

    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _slots: dict[tuple[Any, ...], threading.BoundedSemaphore] = field(
        default_factory=dict
    )

    def _semaphore(
        self, key: tuple[Any, ...], limit: int
    ) -> threading.BoundedSemaphore:
        with self._lock:
            sem = self._slots.get(key)
            if sem is None:
                sem = threading.BoundedSemaphore(limit)
                self._slots[key] = sem
            return sem

    def try_acquire(self, key: tuple[Any, ...], max_in_flight: int) -> bool:
        sem = self._semaphore(key, max_in_flight)
        return sem.acquire(blocking=False)

    def release(self, key: tuple[Any, ...], max_in_flight: int) -> None:
        sem = self._semaphore(key, max_in_flight)
        try:
            sem.release()
        except ValueError:
            raise RuntimeError(f"并发槽位释放溢出: key={key!r}")

    def reset(self) -> None:
        with self._lock:
            self._slots.clear()
