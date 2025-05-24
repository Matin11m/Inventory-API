from odoo import models, fields

class ApiLog(models.Model):
    _name = 'api.log'
    _description = 'API Request Log'
    _order = 'request_time desc'

    user_id = fields.Many2one('res.users', string='User', readonly=True)
    request_time = fields.Datetime(string='Request Time', readonly=True, default=fields.Datetime.now)
    method = fields.Char(string='HTTP Method', readonly=True)
    endpoint = fields.Char(string='Endpoint', readonly=True)
    request_data = fields.Text(string='Request Data', readonly=True)
    response_data = fields.Text(string='Response Data', readonly=True)
    status_code = fields.Integer(string='Status Code', readonly=True)
    response_time_ms = fields.Float(string='Response Time (ms)', readonly=True)