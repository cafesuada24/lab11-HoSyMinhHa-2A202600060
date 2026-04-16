"""
Lab 11 — Auditing System
"""

import json
import time
from collections import defaultdict

type LogEntry = dict[str, object]


class AuditLogger:
    def __init__(self, log_file: str = 'audit_log.json'):
        self.log_file = log_file
        self.logs: list[LogEntry] = []

    def log(self, event_type: str, details: LogEntry) -> None:
        entry = {'timestamp': time.time(), 'event_type': event_type, **details}
        self.logs.append(entry)

    def to_json(self) -> None:
        with open(self.log_file, 'w') as f:
            json.dump(self.logs, f, default=str, ensure_ascii=False)

    def get_summary(self) -> dict:
        """Calculate aggregate stats from the log."""
        total = len(self.logs)
        if total == 0:
            return {'total': 0}

        blocked = sum(1 for e in self.logs if e.get('blocked'))
        latencies = [e['latency_ms'] for e in self.logs if 'latency_ms' in e]
        block_reasons = [
            e.get('block_layer', 'none') for e in self.logs if e.get('blocked')
        ]

        # Most common block reason
        reason_counts = defaultdict(int)
        for r in block_reasons:
            reason_counts[r] += 1
        top_reason = (
            max(reason_counts, key=reason_counts.get) if reason_counts else 'none'
        )

        return {
            'total': total,
            'blocked': blocked,
            'block_rate': round(blocked / total, 3),
            'avg_latency_ms': round(sum(latencies) / len(latencies), 1)
            if latencies
            else 0,
            'top_block_reason': top_reason,
        }
