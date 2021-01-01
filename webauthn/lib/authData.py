from webauthn.lib.utils import bytesToBase64Url
import hashlib
from webauthn.lib.values import Values
from webauthn.lib.exceptions import InvalidValueException


class AuthData:
    def __init__(self, data):
        self.authData = data

        self.rpIdHash = self.authData[0:32]
        flags = self.authData[32:33]
        self.up = (1 & int.from_bytes(flags, byteorder='big')) == 1
        self.uv = (4 & int.from_bytes(flags, byteorder='big')) == 4
        self.signCount = int.from_bytes(
            self.authData[33:37], byteorder='big')
        self.aaguid = self.authData[37:53]

        credentialIdLength = int.from_bytes(
            self.authData[53:55], byteorder='big')
        self.credentialId = bytesToBase64Url(
            self.authData[55:55 + credentialIdLength])
        self.rawPkey = self.authData[55 + credentialIdLength:]

    def validate(self):

        # rpIdHashの確認
        rpIdHash = hashlib.sha256(Values.RP_ID.encode('utf-8')).digest()
        if rpIdHash != self.rpIdHash:
            raise InvalidValueException("rpIdHash")

        # UserPresentの確認
        if not self.up:
            raise InvalidValueException("up")

        # UserVerifiedの確認
        if not self.uv:
            raise InvalidValueException("uv")
