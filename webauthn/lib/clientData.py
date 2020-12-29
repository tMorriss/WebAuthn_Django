from webauthn.lib.utils import base64UrlDecode
from webauthn.lib.exceptions import FormatException, InvalidValueException
from webauthn.lib.values import Values
import json
import os
import hashlib


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

        # typeの確認
        if self.clientDataJson['type'] != 'webauthn.create':
            raise InvalidValueException("clientDataJson.type")

        # challengeの確認
        self.challenge = self.clientDataJson['challenge']
        filepath = self.challenge + ".challenge"
        if not os.path.exists(filepath):
            raise InvalidValueException("clientDataJson.challenge")

        # user.id, user.nameの読み込み
        f = open(filepath, 'r')
        session = f.read()
        f.close()
        os.remove(filepath)

        # originの確認
        if self.clientDataJson['origin'] != Values.ORIGIN:
            raise InvalidValueException("clientDataJson.origin")
