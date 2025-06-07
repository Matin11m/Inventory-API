import json
from datetime import datetime, timedelta


class MonitoringDashboard:
    def __init__(self, env):
        self.env = env

    def get_dashboard_data(self, hours=24):
        """Get comprehensive dashboard data"""
        api_metrics = self.env['api.metrics']

        # Time range
        time_range = datetime.now() - timedelta(hours=hours)
        domain = [('timestamp', '>=', time_range)]

        # Performance Overview
        performance_data = api_metrics.get_performance_stats(hours)

        # Real-time metrics
        realtime_metrics = self._get_realtime_metrics()

        # Alert summary
        alerts = self.env['api.alert'].search([
            ('timestamp', '>=', time_range),
            ('is_resolved', '=', False)
        ])

        alert_summary = {
            'critical': len(alerts.filtered(lambda a: a.severity == 'critical')),
            'warning': len(alerts.filtered(lambda a: a.severity == 'warning')),
            'info': len(alerts.filtered(lambda a: a.severity == 'info')),
        }

        # Response time trends
        response_trends = self._get_response_trends(domain)

        # Top slow endpoints
        slow_endpoints = self._get_slow_endpoints(domain)

        # Error breakdown
        error_breakdown = self._get_error_breakdown(domain)

        return {
            'performance': performance_data,
            'realtime': realtime_metrics,
            'alerts': alert_summary,
            'response_trends': response_trends,
            'slow_endpoints': slow_endpoints,
            'error_breakdown': error_breakdown,
            'generated_at': datetime.now().isoformat()
        }

    def _get_realtime_metrics(self):
        """Get current system metrics"""
        try:
            import psutil
            memory = psutil.virtual_memory()
            cpu = psutil.cpu_percent(interval=1)
            disk = psutil.disk_usage('/')

            return {
                'memory_percent': memory.percent,
                'cpu_percent': cpu,
                'disk_percent': disk.percent,
                'active_connections': len(psutil.net_connections()),
            }
        except Exception:
            return {}

    def _get_response_trends(self, domain):
        """Get response time trends by hour"""
        api_metrics = self.env['api.metrics']

        trends = []
        for i in range(24):
            hour_start = datetime.now() - timedelta(hours=i + 1)
            hour_end = datetime.now() - timedelta(hours=i)
            hour_domain = domain + [
                ('timestamp', '>=', hour_start),
                ('timestamp', '<', hour_end)
            ]

            metrics = api_metrics.search_read(
                hour_domain, ['response_time_ms'], limit=None
            )

            if metrics:
                avg_response_time = sum(m['response_time_ms'] for m in metrics) / len(metrics)
                max_response_time = max(m['response_time_ms'] for m in metrics)
            else:
                avg_response_time = 0
                max_response_time = 0

            trends.append({
                'hour': hour_start.strftime('%H:00'),
                'avg_response_time': round(avg_response_time, 2),
                'max_response_time': round(max_response_time, 2),
                'request_count': len(metrics)
            })

        return list(reversed(trends))

    def _get_slow_endpoints(self, domain, limit=10):
        """Get slowest endpoints"""
        return self.env['api.metrics'].read_group(
            domain,
            ['endpoint', 'response_time_ms:avg'],
            ['endpoint'],
            limit=limit,
            orderby='response_time_ms:avg desc'
        )

    def _get_error_breakdown(self, domain):
        """Get error breakdown by status code"""
        error_domain = domain + [('status_code', '>=', 400)]
        return self.env['api.metrics'].read_group(
            error_domain,
            ['status_code'],
            ['status_code']
        )