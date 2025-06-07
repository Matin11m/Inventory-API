from odoo import models, fields, api
import json
import psutil
import time
from datetime import datetime, timedelta


class ApiMetrics(models.Model):
    _name = 'api.metrics'
    _description = 'API Performance Metrics'
    _order = 'timestamp desc'

    timestamp = fields.Datetime(default=fields.Datetime.now, index=True)
    endpoint = fields.Char(string='Endpoint', index=True)
    method = fields.Char(string='HTTP Method')
    user_id = fields.Many2one('res.users', string='User')
    ip_address = fields.Char(string='IP Address')
    user_agent = fields.Text(string='User Agent')

    # Performance Metrics
    response_time_ms = fields.Float(string='Response Time (ms)', index=True)
    memory_usage_mb = fields.Float(string='Memory Usage (MB)')
    cpu_percent = fields.Float(string='CPU Usage %')
    db_queries_count = fields.Integer(string='DB Queries Count')

    # Request/Response Details
    request_size_bytes = fields.Integer(string='Request Size (bytes)')
    response_size_bytes = fields.Integer(string='Response Size (bytes)')
    status_code = fields.Integer(string='Status Code', index=True)

    # Rate Limiting
    rate_limit_remaining = fields.Integer(string='Rate Limit Remaining')
    rate_limit_reset_time = fields.Datetime(string='Rate Limit Reset Time')

    # Error Details
    error_message = fields.Text(string='Error Message')
    error_traceback = fields.Text(string='Error Traceback')

    # Business Metrics
    products_affected = fields.Integer(string='Products Affected')
    stock_changes = fields.Integer(string='Stock Changes')

    @api.model
    def get_performance_stats(self, hours=24):
        """Get performance statistics for dashboard"""
        domain = [('timestamp', '>=', fields.Datetime.now() - timedelta(hours=hours))]

        # Basic stats
        total_requests = self.search_count(domain)
        avg_response_time = self.search_read(domain, ['response_time_ms'], limit=None)
        avg_response_time = sum([r['response_time_ms'] for r in avg_response_time]) / len(
            avg_response_time) if avg_response_time else 0

        # Error rate
        error_domain = domain + [('status_code', '>=', 400)]
        error_count = self.search_count(error_domain)
        error_rate = (error_count / total_requests * 100) if total_requests > 0 else 0

        # Top endpoints
        endpoint_stats = self.read_group(
            domain, ['endpoint', 'response_time_ms:avg'], ['endpoint']
        )

        # Hourly distribution
        hourly_stats = []
        for i in range(24):
            hour_start = fields.Datetime.now() - timedelta(hours=i + 1)
            hour_end = fields.Datetime.now() - timedelta(hours=i)
            hour_domain = [
                ('timestamp', '>=', hour_start),
                ('timestamp', '<', hour_end)
            ]
            hour_count = self.search_count(hour_domain)
            hourly_stats.append({
                'hour': hour_start.hour,
                'requests': hour_count
            })

        return {
            'total_requests': total_requests,
            'avg_response_time': round(avg_response_time, 2),
            'error_rate': round(error_rate, 2),
            'top_endpoints': endpoint_stats,
            'hourly_distribution': hourly_stats
        }


class ApiAlert(models.Model):
    _name = 'api.alert'
    _description = 'API Monitoring Alerts'
    _order = 'timestamp desc'

    timestamp = fields.Datetime(default=fields.Datetime.now)
    alert_type = fields.Selection([
        ('high_response_time', 'High Response Time'),
        ('high_error_rate', 'High Error Rate'),
        ('rate_limit_exceeded', 'Rate Limit Exceeded'),
        ('high_memory_usage', 'High Memory Usage'),
        ('high_cpu_usage', 'High CPU Usage'),
        ('endpoint_down', 'Endpoint Down'),
    ], string='Alert Type', required=True)

    severity = fields.Selection([
        ('info', 'Info'),
        ('warning', 'Warning'),
        ('critical', 'Critical'),
    ], string='Severity', default='warning')

    endpoint = fields.Char(string='Affected Endpoint')
    metric_value = fields.Float(string='Metric Value')
    threshold_value = fields.Float(string='Threshold Value')
    message = fields.Text(string='Alert Message')

    # Status
    is_resolved = fields.Boolean(string='Resolved', default=False)
    resolved_at = fields.Datetime(string='Resolved At')
    resolved_by = fields.Many2one('res.users', string='Resolved By')

    # Notification
    notification_sent = fields.Boolean(string='Notification Sent', default=False)
    notification_channels = fields.Char(string='Notification Channels')
