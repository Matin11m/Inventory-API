from datetime import datetime, timedelta
from functools import wraps
from threading import Lock
from odoo import http
from odoo.http import request
import json
import logging
import time

_logger = logging.getLogger(__name__)


class RateLimiter:
    def __init__(self, cleanup_interval=3600):
        self.requests_user = {}
        self.requests_ip = {}
        self.lock = Lock()
        self.last_cleanup = time.time()
        self.cleanup_interval = cleanup_interval

    def _cleanup(self):
        now = time.time()
        if now - self.last_cleanup > self.cleanup_interval:
            with self.lock:
                self.requests_user = {
                    k: v for k, v in self.requests_user.items()
                    if v and (now - v[-1].timestamp()) < (self.cleanup_interval * 2)
                }
                self.requests_ip = {
                    k: v for k, v in self.requests_ip.items()
                    if v and (now - v[-1].timestamp()) < (self.cleanup_interval * 2)
                }
                self.last_cleanup = now

    def is_allowed(self, user_id, ip, max_requests, time_window):
        self._cleanup()
        with self.lock:
            now = datetime.now()
            if user_id not in self.requests_user:
                self.requests_user[user_id] = []
            self.requests_user[user_id] = [
                t for t in self.requests_user[user_id] if now - t < timedelta(seconds=time_window)
            ]
            if ip not in self.requests_ip:
                self.requests_ip[ip] = []
            self.requests_ip[ip] = [
                t for t in self.requests_ip[ip] if now - t < timedelta(seconds=time_window)
            ]

            user_requests_count = len(self.requests_user[user_id])
            ip_requests_count = len(self.requests_ip[ip])

            if user_requests_count >= max_requests or ip_requests_count >= max_requests:
                _logger.warning(
                    f"Rate limit exceeded for user {user_id} (count: {user_requests_count}) or IP {ip} (count: {ip_requests_count}). "
                    f"Limit: max_requests={max_requests}, time_window={time_window}s"
                )
                return False

            self.requests_user[user_id].append(now)
            self.requests_ip[ip].append(now)
            _logger.debug(
                f"Request allowed for user {user_id}, IP {ip}. "
                f"User count: {len(self.requests_user[user_id])}/{max_requests}, "
                f"IP count: {len(self.requests_ip[ip])}/{max_requests}"
            )
            return True


def rate_limited(limiter_instance, max_requests, time_window):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user_id = request.env.user.id
            ip = request.httprequest.remote_addr
            if not limiter_instance.is_allowed(user_id, ip, max_requests, time_window):
                return http.Response(
                    json.dumps({'error': 'Too many requests, please try again later.'}),
                    status=429,
                    content_type='application/json'
                )
            return f(*args, **kwargs)

        return wrapper

    return decorator
