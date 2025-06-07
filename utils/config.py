ALLOWED_FIELDS = ['name', 'default_code', 'list_price', 'type']
MAX_PRODUCTS = 100
UNIQUE_FIELDS = ['name', 'default_code']
DEFAULT_STOCK_LOCATION = 'Stock'
MAX_LOG_SIZE = 1024 * 1024  # 1MB

ALLOWED_IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif'}

ALLOWED_IMAGE_MIME_TYPES = {'image/jpeg', 'image/png', 'image/gif'}

MAX_PRODUCTS = 100

MAX_IMAGES = 100

BATCH_SIZE = 50

TIMEOUT_SECONDS = 300

MAX_INVOICE_LINES = 100