import hashlib
import json
from webauthn.models import Session
from webauthn.lib.values import Values
from webauthn.lib.exceptions import FormatException, InvalidValueException
from webauthn.lib.utils import base64UrlDecode
from django.utils import timezone
from datetime import timedelta


class ClientData:
    def __init__(self, raw):

        # デコード
        clientData = base64UrlDecode(raw).decode('utf-8')
        self.hash = hashlib.sha256(
            clientData.encode('utf-8')).digest()
        try:
            self.clientDataJson = json.loads(clientData)
        except json.decoder.JSONDecodeError:
            raise FormatException('clientDataJSON')

    def validate(self):
        # 存在確認
        if 'type' not in self.clientDataJson:
            raise FormatException("clientDataJson.type")
        if 'challenge' not in self.clientDataJson:
            raise FormatException("clientDataJson.challenge")
        if 'origin' not in self.clientDataJson:
            raise FormatException("clientDataJson.origin")

        # typeの確認
        if self.clientDataJson['type'] != 'webauthn.create':
            raise InvalidValueException("clientDataJson.type")

        # challengeを取り出す
        self.challenge = self.clientDataJson['challenge']

        # originの確認
        if self.clientDataJson['origin'] != Values.ORIGIN:
            raise InvalidValueException("clientDataJson.origin")
