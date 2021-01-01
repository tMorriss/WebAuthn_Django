from webauthn.lib.utils import base64UrlDecode
from webauthn.lib.exceptions import FormatException, InvalidValueException, UnsupportedException
from webauthn.lib.values import Values
from webauthn.lib.authData import AuthData
from webauthn.lib.publicKey import PublicKey
import cbor2
from Crypto.PublicKey import RSA


class AttestationStatement:
    pass


class Packed(AttestationStatement):
    def __init__(self, attStmt):
        # validate
        if 'alg' not in attStmt:
            raise FormatException('alg')
        if 'sig' not in attStmt:
            raise FormatException('sig')

        self.attStmt = attStmt
        self.alg = attStmt['alg']

    def validate(self, dataToVerify, pubKey):
        # algが対応していることの確認
        if self.alg not in Values.ALG_LIST.values():
            self.errorMsg = 'alg'
            return False

        if "x5c" not in self.attStmt:
            if not PublicKey.verify(pubKey, dataToVerify,
                                    self.attStmt['sig'], self.alg):
                raise InvalidValueException("attStmt.sig")
        else:
            raise UnsupportedException("packed with x5c")


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

        if pkey[1] == Values.KTY_RSA and pkey[3] == Values.ALG_LIST['RS256']:
            self.alg = pkey[3]
            # RSA256
            if pkey.keys() <= {- 1, -2}:
                raise FormatException("rs256")

            n = int.from_bytes(pkey[-1], byteorder='big')
            e = int.from_bytes(pkey[-2], byteorder='big')
            return RSA.construct((n, e))

        raise UnsupportedException("pubKey alg")

    def validateAttStmt(self, clientDataHash):

        # fmtに対応したvalidatorを読み込み
        attStmt = None
        if self.fmt == Values.FMT_LIST['packed']:
            attStmt = Packed(self.attStmt)
        else:
            raise UnsupportedException("attestationObject.fmt=" + self.fmt)

        dataToVerify = self.authData.authData + clientDataHash
        self.credentialPublicKey = self.__extractPubKey()

        # それぞれのattStmtの検証
        attStmt.validate(dataToVerify, self.credentialPublicKey)
