from datetime import datetime, timedelta
from functools import wraps

from odoo import http
from odoo.http import request
import json
import logging

_logger = logging.getLogger(__name__)


class RateLimiter:
    def __init__(self):
        self.requests = {}

    def is_allowed(self, user_id, max_requests, time_window):

        now = datetime.now()

        if user_id not in self.requests:
            self.requests[user_id] = []

        self.requests[user_id] = [t for t in self.requests[user_id] if now - t < timedelta(seconds=time_window)]

        if len(self.requests[user_id]) >= max_requests:
            return False

        self.requests[user_id].append(now)
        return True


def rate_limited(rate_limiter, max_requests, time_window):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user_id = request.env.user.id
            if not rate_limiter.is_allowed(user_id, max_requests, time_window):
                return http.Response(
                    json.dumps({'error': 'Too many requests, please try again later.'}),
                    status=429,
                    content_type='application/json'
                )
            return f(*args, **kwargs)

        return wrapper

    return decorator
