import hashlib
import json

from webauthn.lib.exceptions import FormatException, InvalidValueException
from webauthn.lib.utils import base64_url_decode
from webauthn.lib.values import Values


class ClientData:
    def __init__(self, raw):

        # デコード
        client_data = base64_url_decode(raw).decode('utf-8')
        self.hash = hashlib.sha256(
            client_data.encode('utf-8')).digest()
        try:
            self.client_data_json = json.loads(client_data)
        except json.decoder.JSONDecodeError:
            raise FormatException('clientDataJSON')

    def __validate(self, function):
        # 存在確認
        if 'type' not in self.client_data_json:
            raise FormatException("clientDataJson.type")
        if 'challenge' not in self.client_data_json:
            raise FormatException("clientDataJson.challenge")
        if 'origin' not in self.client_data_json:
            raise FormatException("clientDataJson.origin")

        # typeの確認
        if self.client_data_json['type'] != 'webauthn.' + function:
            raise InvalidValueException("clientDataJson.type")

        # challengeを取り出す
        self.challenge = self.client_data_json['challenge']

        # originの確認
        if self.client_data_json['origin'] != Values.ORIGIN:
            raise InvalidValueException("clientDataJson.origin")

    def validate_create(self):
        self.__validate("create")

    def validate_get(self):
        self.__validate("get")
