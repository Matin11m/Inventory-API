# from odoo import models, fields
# from datetime import timedelta
#
#
# class ApiLog(models.Model):
#     _name = 'api.log'
#     _description = 'API Request Log'
#
#     user_id = fields.Many2one('res.users', string='User')
#     path = fields.Char(string='Endpoint')
#     ip_address = fields.Char(string='IP Address')
#     method = fields.Char(string='Method')
#     params = fields.Text(string='Parameters')
#     status_code = fields.Integer(string='Status')
#     timestamp = fields.Datetime(string='Timestamp', default=fields.Datetime.now)
#     response_time = fields.Float(string='Response Time (ms)')
#
#     def _cron_cleanup_old_logs(self, days=30):
#         limit_date = fields.Datetime.now() - timedelta(days=days)
#         old_logs = self.search([('timestamp', '<', limit_date)])
#         old_logs.unlink()
