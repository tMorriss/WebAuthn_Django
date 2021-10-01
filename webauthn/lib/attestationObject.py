import cbor2
from Crypto.PublicKey import ECC, RSA
from webauthn.lib.attestationStatement import (
    AndroidSafetyNet, Apple, Packed, Tpm)
from webauthn.lib.authData import AuthData
from webauthn.lib.exceptions import FormatException, UnsupportedException
from webauthn.lib.metadata import MetaDataService
from webauthn.lib.utils import base64_url_decode
from webauthn.lib.values import Values


class AttestationObject:

    def __init__(self, raw):
        cbor = cbor2.loads(base64_url_decode(raw))

        # validate
        if 'fmt' not in cbor:
            raise FormatException('attestationObject.fmt')
        if 'attStmt' not in cbor:
            raise FormatException('attestationObject.attStmt')
        if 'authData' not in cbor:
            raise FormatException('attestationObject.authData')

        self.fmt = cbor['fmt']
        self.att_stmt = cbor['attStmt']
        self.auth_data = AuthData(cbor['authData'])

    def __extract_pub_key(self):
        pkey = cbor2.loads(self.auth_data.raw_pub_key)
        if pkey.keys() <= {1, 3}:
            raise FormatException("pkey")

        if pkey[1] == Values.KTY_LIST['RSA'] and pkey[3] == Values.ALG_LIST['RS256']:
            self.alg = pkey[3]
            if pkey.keys() <= {- 1, -2}:
                raise FormatException("rs256")

            n = int.from_bytes(pkey[-1], byteorder='big')
            e = int.from_bytes(pkey[-2], byteorder='big')
            return RSA.construct((n, e)).export_key(format='PEM').decode()

        if pkey[1] == Values.KTY_LIST['EC2'] and pkey[3] == Values.ALG_LIST['ES256']:
            self.alg = pkey[3]
            if pkey.keys() <= {- 1, -2, -3}:
                raise FormatException("es256")

            curve = Values.EC_KEYS[pkey[-1]]
            x = int.from_bytes(pkey[-2], byteorder='big')
            y = int.from_bytes(pkey[-3], byteorder='big')
            return ECC.construct(curve=curve, point_x=x, point_y=y).export_key(format='PEM')

        raise UnsupportedException("pubKey alg")

    def validate_att_stmt(self, client_data_hash):

        # fmtに対応したvalidatorを読み込み
        att_stmt = None
        if self.fmt == 'packed':
            att_stmt = Packed(self.att_stmt)
        elif self.fmt == 'android-safetynet':
            metadata = MetaDataService()
            metadata.get(self.auth_data.aaguid)

            att_stmt = AndroidSafetyNet(self.att_stmt)
            att_stmt.add_root_certificate(metadata)
        elif self.fmt == 'apple':
            att_stmt = Apple(self.att_stmt)
        elif self.fmt == 'tpm':
            att_stmt = Tpm(self.att_stmt)
        else:
            raise UnsupportedException("attestationObject.fmt=" + self.fmt)

        data_to_verify = self.auth_data.auth_data + client_data_hash
        self.credential_public_key = self.__extract_pub_key()

        # それぞれのattStmtの検証
        att_stmt.validate(data_to_verify, self.credential_public_key)
