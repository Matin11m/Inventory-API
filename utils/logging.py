import logging
import json

from odoo import fields
from odoo.exceptions import AccessError
from ..utils import config

_logger = logging.getLogger(__name__)


def log_error(error_message, exception=None):
    _logger.error(f"Error: {error_message}")
    if exception:
        _logger.exception(exception)


def log_api_request(env, user_id, method, endpoint, request_data, response_data, status_code, response_time_ms,
                    log_level='info'):
    try:
        is_admin = env.user.has_group('base.group_system')
        if not is_admin:
            logging.getLogger('odoo.addons.inventory_api.utils.logging').warning(
                "User %s does not have admin privileges to log API requests", user_id
            )
            return

        request_data_str = request_data if isinstance(request_data, str) else json.dumps(request_data, default=str)
        response_data_str = response_data if isinstance(response_data, str) else json.dumps(response_data, default=str)

        max_log_size = getattr(config, 'MAX_LOG_SIZE', 1000)
        if len(request_data_str) > max_log_size:
            request_data_str = request_data_str[:max_log_size] + "... [Truncated]"
        if len(response_data_str) > max_log_size:
            response_data_str = response_data_str[:max_log_size] + "... [Truncated]"

        env['api.log'].create({
            'user_id': user_id,
            'request_time': fields.Datetime.now(),
            'method': method,
            'endpoint': endpoint,
            'request_data': request_data_str,
            'response_data': response_data_str,
            'status_code': status_code,
            'response_time_ms': response_time_ms,
        })

        logger = logging.getLogger('odoo.addons.inventory_api.utils.logging')
        if log_level == 'debug':
            logger.debug("API Log: user=%s, endpoint=%s, status=%s", user_id, endpoint, status_code)
        elif log_level == 'error':
            logger.error("API Log: user=%s, endpoint=%s, error: %s", user_id, endpoint, request_data_str)
        else:
            logger.info("API Log: user=%s, endpoint=%s, status=%s", user_id, endpoint, status_code)

    except Exception as e:
        logging.getLogger('odoo.addons.inventory_api.utils.logging').error(
            "Failed to log API request: %s", str(e)
        )
