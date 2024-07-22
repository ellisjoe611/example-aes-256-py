import json
from typing import Any

from marshmallow import Schema, fields, post_dump, pre_load

from encrypt import AESCipherV2, AESCipher


class SchemaEncryptionMixinV2:
    __cipher = AESCipherV2(key="my_encryption_key")

    @pre_load
    def decrypt_request_body(self, data, **kwargs) -> Any:
        if not isinstance(data, str):
            raise TypeError("Not encrypted string.")

        try:
            return json.loads(self.__cipher.decrypt(ciphertext=data))
        except Exception:
            raise Exception("Decryption failed.")

    @post_dump
    def encrypt_response_body(self, data, **kwargs) -> str:
        try:
            return self.__cipher.encrypt(plaintext=json.dumps(data))
        except Exception:
            raise Exception("Encryption failed.")


class SchemaEncryptionMixin:
    __cipher = AESCipher(keytext="my_encryption_key")

    @pre_load
    def decrypt_request_body(self, data, **kwargs) -> Any:
        if not isinstance(data, str):
            raise TypeError("Data must be encrypted string.")

        try:
            decrypted_text = self.__cipher.decrypt(encrypted=data.encode("utf-8"))
            return json.loads(decrypted_text)
        except Exception:
            raise Exception("Decryption failed.")

    @post_dump
    def encrypt_response_body(self, data, **kwargs) -> str:
        try:
            encrypted_bytes = self.__cipher.encrypt(plaintext=json.dumps(data))
            return encrypted_bytes.decode("utf-8")
        except Exception:
            raise Exception("Encryption failed.")


class PersonalInfoSchema(Schema):
    ssn = fields.String(required=True)
    phone = fields.String(required=True)


class MyInfoSchema(Schema, SchemaEncryptionMixin):
    name = fields.String(required=True)
    age = fields.Integer(required=True)
    is_admin = fields.Boolean(missing=False)
    personal_info = fields.Nested(PersonalInfoSchema)
    tags = fields.List(fields.String, allow_none=False)


if __name__ == "__main__":
    single_schema = MyInfoSchema()
    single_data = {
        "name": "python user 03",
        "age": 30,
        "is_admin": True,
        "personal_info": {"ssn": "123123", "phone": "456456"},
        "tags": ["tag1", "tag2", "tag3"],
    }

    dumped_str = single_schema.dump(single_data)
    print(f"single dump:\t{type(dumped_str)}\n{dumped_str}\n")

    loaded_object = single_schema.load(dumped_str)
    print(f"single load:\t{type(loaded_object)}\n{loaded_object}\n\n")

    many_schema = MyInfoSchema(many=True)
    list_data = [
        {
            "name": "python user 01",
            "age": 28,
            "is_admin": False,
            "personal_info": {"ssn": "010101", "phone": "010"},
            "tags": [],
        },
        {
            "name": "python user 02",
            "age": 29,
            "is_admin": False,
            "personal_info": {"ssn": "020202", "phone": "020"},
            "tags": ["tag1"],
        },
        {
            "name": "python user 03",
            "age": 30,
            "is_admin": True,
            "personal_info": {"ssn": "123123", "phone": "456456"},
            "tags": ["tag1", "tag2", "tag3"],
        },
    ]

    dumped_str_many = many_schema.dump(list_data)
    print(f"multiple dump:\t{type(dumped_str_many)}\n{dumped_str_many}\n")

    loaded_object_many = many_schema.load(dumped_str_many)
    print(f"multiple load:\t{type(loaded_object_many)}\n{loaded_object_many}\n\n")

    dumped_str_from_js = (
        "klUdduy+yTt9v2ylgfQ8p/hiXyKEa1cGlpmP8t74WEJgCr4frJZEXfx22lRrYhZCE9nqn8/98u3if9l+5d7JjvZhImqvlaCfPMmxXfa6eP1O5BfGLFo1zfv17t+LwJKAi9RnpTW0PaW+ggpzduUzQPHAJFhdPrj4zLs0qnvJwX8wIc4bulByPlKeFANJgZXSvzL2NiqOA1fkC50O25dqGQ=="
    )
    loaded_object_from_js = single_schema.load(dumped_str_from_js)
    print(f"loaded from js:\t{type(loaded_object_from_js)}\n{loaded_object_from_js}\n\n")
