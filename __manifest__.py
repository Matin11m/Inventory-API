{
    'name': 'Inventory API',
    'version': '1.0',
    'description': """
    The Inventory API module provides a secure REST API for accessing product and stock data in Odoo.
    This module allows third-party applications to retrieve product and stock information through a set of
    well-defined endpoints while ensuring security through JWT-based authentication.

    Features:
    - JWT-based authentication for secure access
    - Rate limiting to prevent abuse and DDoS attacks
    - Pagination and flexible filtering for data retrieval
    - Dynamic field selection for API responses
    - Support for CRUD operations on inventory-related data

    This module is designed to integrate seamlessly with Odoo’s stock and product modules.
    """,
    'depends': ['base', 'product', 'stock'],
    'data': [
        'security/security_groups.xml',
        'security/ir.model.access.csv',
        'views/api_log_views.xml',
    ],
    'installable': True,
    'auto_install': False,
    'application': False,
    'license': 'AGPL-3',
    'author': 'Matin Shahmaleki',
    'category': 'Inventory',
    'sequence': 10,
    'maintainer': 'matin.shahmaleki001@gmail.com',
    'external_dependencies': {'python': ['requests', 'pyjwt']},
}
