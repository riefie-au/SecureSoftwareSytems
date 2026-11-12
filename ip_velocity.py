from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
request_history = defaultdict(deque)

MAX_REQUESTS = 20
WINDOW_SECONDS = 60


def check_ip_velocity(ip: str) -> bool:
    now = datetime.now(timezone.utc)
    history = request_history[ip]

    cutoff = now - timedelta(seconds=WINDOW_SECONDS)

    while history and history[0] <= cutoff:
        history.popleft()

    if len(history) >= MAX_REQUESTS:
        return False

    history.append(now)
    return True