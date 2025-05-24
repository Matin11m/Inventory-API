from ..utils.validators import validate_username, validate_password, validate_limit_offset, \
    extract_valid_fields
from odoo.tests.common import TransactionCase


class TestValidators(TransactionCase):
    test_tags = ['validator', 'test']

    def setUp(self):
        super(TestValidators, self).setUp()

    def test_validate_username(self):
        valid_username = "test_user123"
        invalid_username = "test$user123"

        self.assertEqual(validate_username(valid_username), valid_username)

        with self.assertRaises(ValueError):
            validate_username(invalid_username)

    def test_validate_password(self):
        valid_password = "Password123"
        invalid_password = "short"

        self.assertEqual(validate_password(valid_password), valid_password)

        with self.assertRaises(ValueError):
            validate_password(invalid_password)

    def test_validate_limit_offset(self):
        valid_kwargs = {'limit': 10, 'offset': 0}
        invalid_kwargs = {'limit': -1, 'offset': 0}

        limit, offset = validate_limit_offset(valid_kwargs)
        self.assertEqual(limit, 10)
        self.assertEqual(offset, 0)

        with self.assertRaises(ValueError):
            validate_limit_offset(invalid_kwargs)

    def test_extract_valid_fields(self):
        fields_param = "id,name,default_code"
        model_fields = ['id', 'name', 'default_code', 'list_price']

        valid_fields = extract_valid_fields(fields_param, model_fields, ['id', 'name'])
        self.assertEqual(valid_fields, ['id', 'name'])

        with self.assertRaises(ValueError):
            extract_valid_fields("invalid_field", model_fields, ['id', 'name'])
