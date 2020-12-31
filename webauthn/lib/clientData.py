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

        # typeの確認
        if self.clientDataJson['type'] != 'webauthn.create':
            raise InvalidValueException("clientDataJson.type")

        # challengeの確認
        self.challenge = self.clientDataJson['challenge']
        session = Session.objects.filter(challenge=self.challenge)
        if session.count() != 1:
            raise InvalidValueException("clientDataJson.challenge")
        session = session.first()

        # 時刻確認
        if session.time >= timezone.now() + timedelta(minutes=Values.SESSION_TIMEOUT_MINUTE):
            raise InvalidValueException("session timeout")

        # 名前を取り出す
        self.username = session.username

        # session削除
        session.delete()

        # originの確認
        if self.clientDataJson['origin'] != Values.ORIGIN:
            raise InvalidValueException("clientDataJson.origin")
