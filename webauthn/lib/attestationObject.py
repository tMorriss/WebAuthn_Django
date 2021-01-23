from Crypto.PublicKey import RSA, ECC
from webauthn.lib.attestationStatement import Packed, AndroidSafetyNet, Apple
from webauthn.lib.authData import AuthData
from webauthn.lib.exceptions import FormatException,  UnsupportedException
from webauthn.lib.utils import base64UrlDecode
from webauthn.lib.values import Values
from webauthn.lib.metadata import MetaDataService
import cbor2


class AttestationObject:

    def __init__(self, raw):
        cbor = cbor2.loads(base64UrlDecode(raw))

        # validate
        if 'fmt' not in cbor:
            raise FormatException('attestationObject.fmt')
        if 'attStmt' not in cbor:
            raise FormatException('attestationObject.attStmt')
        if 'authData' not in cbor:
            raise FormatException('attestationObject.authData')

        self.fmt = cbor['fmt']
        self.attStmt = cbor['attStmt']
        self.authData = AuthData(cbor['authData'])

    def __extractPubKey(self):
        pkey = cbor2.loads(self.authData.rawPkey)
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

    def validateAttStmt(self, clientDataHash):

        # fmtに対応したvalidatorを読み込み
        attStmt = None
        if self.fmt == 'packed':
            attStmt = Packed(self.attStmt)
        elif self.fmt == 'android-safetynet':
            metadata = MetaDataService()
            metadata.get(self.authData.aaguid)

            attStmt = AndroidSafetyNet(self.attStmt)
            attStmt.add_root_certificate(metadata)
        elif self.fmt == 'apple':
            attStmt = Apple(self.attStmt)
        else:
            raise UnsupportedException("attestationObject.fmt=" + self.fmt)

        dataToVerify = self.authData.authData + clientDataHash
        self.credentialPublicKey = self.__extractPubKey()

        # それぞれのattStmtの検証
        attStmt.validate(dataToVerify, self.credentialPublicKey)
