"""
Lab 11 — Rate Limiting
"""

import time
import collections


class RateLimiter:
    def __init__(self, max_calls: int, period: int):
        self.max_calls = max_calls
        self.period = period
        self.user_history = collections.defaultdict(collections.deque)
        self.total_checks = 0
        self.total_blocks = 0

    def allow_request(self, user_id: str = 'default') -> dict:
        self.total_checks += 1
        now = time.time()
        history = self.user_history[user_id]

        while history and history[0] < now - self.period:
            history.popleft()

        if len(history) < self.max_calls:
            history.append(now)
            remaining = self.max_calls - len(history)
            return {'allowed': True, 'wait_seconds': 0.0, 'remaining': remaining}

        self.total_blocks += 1
        wait_seconds = self.period - (now - history[0])
        return {
            'allowed': False,
            'wait_seconds': round(max(0.0, wait_seconds), 1),
            'remaining': 0,
        }


# Test
if __name__ == '__main__':
    rl = RateLimiter(max_calls=3, period=5)
    for i in range(5):
        r = rl.allow_request('test_user')
        print(
            f'  Request {i + 1}: allowed={r["allowed"]}, remaining={r["remaining"]}, wait={r["wait_seconds"]}s'
        )
    del rl
