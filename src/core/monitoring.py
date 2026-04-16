"""
Lab 11 — Monitoring System
"""
import collections
import time

class SecurityMonitor:
    def __init__(self, window_size: int = 10):
        self.events = collections.deque(maxlen=window_size)

    def record_event(self, event_type: str, blocked: bool):
        self.events.append((time.time(), event_type, blocked))
        self.check_thresholds()

    def check_thresholds(self):
        blocked_count = sum(1 for _, _, blocked in self.events if blocked)
        if blocked_count > 5:
            print(f"[ALERT] High frequency of blocked requests detected: {blocked_count}/10")

