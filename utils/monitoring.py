import psutil
import time
import threading
from functools import wraps
from datetime import datetime, timedelta
import logging

_logger = logging.getLogger(__name__)


class AdvancedMonitoring:
    def __init__(self):
        self.metrics_buffer = []
        self.alert_thresholds = {
            'response_time_threshold': 2000,  # 2 seconds
            'error_rate_threshold': 5,  # 5%
            'memory_threshold': 80,  # 80%
            'cpu_threshold': 80,  # 80%
        }
        self._start_system_monitor()

    def _start_system_monitor(self):
        """Background thread for system monitoring"""

        def monitor():
            while True:
                try:
                    self._collect_system_metrics()
                    time.sleep(60)  # Collect every minute
                except Exception as e:
                    _logger.error(f"System monitoring error: {e}")

        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()

    def _collect_system_metrics(self):
        """Collect system-wide metrics"""
        try:
            memory = psutil.virtual_memory()
            cpu = psutil.cpu_percent(interval=1)
            disk = psutil.disk_usage('/')

            system_metrics = {
                'timestamp': datetime.now(),
                'memory_percent': memory.percent,
                'memory_available_gb': memory.available / (1024 ** 3),
                'cpu_percent': cpu,
                'disk_percent': disk.percent,
                'disk_free_gb': disk.free / (1024 ** 3),
            }

            # Check for alerts
            self._check_system_alerts(system_metrics)

        except Exception as e:
            _logger.error(f"Error collecting system metrics: {e}")

    def _check_system_alerts(self, metrics):
        """Check if system metrics exceed thresholds"""
        alerts = []

        if metrics['memory_percent'] > self.alert_thresholds['memory_threshold']:
            alerts.append({
                'type': 'high_memory_usage',
                'severity': 'critical',
                'value': metrics['memory_percent'],
                'threshold': self.alert_thresholds['memory_threshold'],
                'message': f"Memory usage is {metrics['memory_percent']:.1f}%"
            })

        if metrics['cpu_percent'] > self.alert_thresholds['cpu_threshold']:
            alerts.append({
                'type': 'high_cpu_usage',
                'severity': 'warning',
                'value': metrics['cpu_percent'],
                'threshold': self.alert_thresholds['cpu_threshold'],
                'message': f"CPU usage is {metrics['cpu_percent']:.1f}%"
            })

        # Store alerts if any
        if alerts:
            self._store_alerts(alerts)

    def _store_alerts(self, alerts):
        """Store alerts in database"""
        # This would be called with proper Odoo environment
        pass


def advanced_monitor(env=None):
    """Advanced monitoring decorator"""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            start_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
            start_cpu = psutil.Process().cpu_percent()

            # Count DB queries (if in Odoo context)
            initial_query_count = 0
            if env and hasattr(env, 'cr'):
                initial_query_count = env.cr.sql_log_count if hasattr(env.cr, 'sql_log_count') else 0

            try:
                result = func(*args, **kwargs)
                status_code = getattr(result, 'status_code', 200)

                # Calculate metrics
                end_time = time.time()
                response_time_ms = (end_time - start_time) * 1000
                end_memory = psutil.Process().memory_info().rss / 1024 / 1024
                memory_usage = end_memory - start_memory
                cpu_usage = psutil.Process().cpu_percent()

                # DB queries count
                final_query_count = 0
                if env and hasattr(env, 'cr'):
                    final_query_count = env.cr.sql_log_count if hasattr(env.cr, 'sql_log_count') else 0
                db_queries = final_query_count - initial_query_count

                # Store metrics
                if env:
                    _store_advanced_metrics(env, {
                        'endpoint': getattr(func, '__name__', 'unknown'),
                        'response_time_ms': response_time_ms,
                        'memory_usage_mb': memory_usage,
                        'cpu_percent': cpu_usage,
                        'db_queries_count': db_queries,
                        'status_code': status_code,
                        'timestamp': datetime.now(),
                    })

                return result

            except Exception as e:
                # Store error metrics
                end_time = time.time()
                response_time_ms = (end_time - start_time) * 1000

                if env:
                    _store_advanced_metrics(env, {
                        'endpoint': getattr(func, '__name__', 'unknown'),
                        'response_time_ms': response_time_ms,
                        'status_code': 500,
                        'error_message': str(e),
                        'timestamp': datetime.now(),
                    })

                raise

        return wrapper

    return decorator


def _store_advanced_metrics(env, metrics_data):
    """Store metrics in database"""
    try:
        env['api.metrics'].sudo().create(metrics_data)
    except Exception as e:
        _logger.error(f"Error storing metrics: {e}")