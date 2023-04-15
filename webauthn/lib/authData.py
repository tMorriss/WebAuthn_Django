import hashlib

from webauthn.lib.exceptions import InvalidValueException
from webauthn.lib.utils import bytes_to_base64_url
from webauthn.lib.values import Values


class AuthData:
    def __init__(self, data):
        self.auth_data = data

        self.rpid_hash = self.auth_data[0:32]
        flags = self.auth_data[32:33]
        self.up = (1 & int.from_bytes(flags, byteorder='big')) == 1
        self.uv = (4 & int.from_bytes(flags, byteorder='big')) == 4
        self.be = (8 & int.from_bytes(flags, byteorder='big')) == 8
        self.bs = (16 & int.from_bytes(flags, byteorder='big')) == 16
        self.sign_count = int.from_bytes(
            self.auth_data[33:37], byteorder='big')
        self.aaguid = self.auth_data[37:53].hex()

        credential_id_length = int.from_bytes(
            self.auth_data[53:55], byteorder='big')
        self.credential_id = bytes_to_base64_url(
            self.auth_data[55:55 + credential_id_length])
        self.raw_pub_key = self.auth_data[55 + credential_id_length:]

    def validate(self):

        # rpIdHashの確認
        rpid_hash = hashlib.sha256(Values.RP_ID.encode('utf-8')).digest()
        if rpid_hash != self.rpid_hash:
            raise InvalidValueException("rpIdHash")

        # UserPresentの確認
        if not self.up:
            raise InvalidValueException("up")

        # UserVerifiedの確認
        if not self.uv:
            raise InvalidValueException("uv")
