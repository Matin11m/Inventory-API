import logging

_logger = logging.getLogger(__name__)

def log_error(error_message, exception=None):
    _logger.error(f"Error: {error_message}")
    if exception:
        _logger.exception(exception)