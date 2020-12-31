from webauthn.lib.utils import base64UrlDecode, bytesToBase64Url
from webauthn.lib.exceptions import FormatException, InvalidValueException, UnsupportedException
from webauthn.lib.values import Values
import cbor2
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15


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
            h = SHA256.new(dataToVerify)
            try:
                pkcs1_15.new(pubKey).verify(h, self.attStmt['sig'])
            except ValueError:
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

        self.authData = cbor['authData']
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

    def extractPubKey(self):
        pkey = cbor2.loads(self.rawPkey)
        if pkey.keys() <= {1, 3}:
            raise FormatException("pkey")

        if pkey[1] == Values.KTY_RSA and pkey[3] == Values.ALG_LIST['RS256']:
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

        dataToVerify = self.authData + clientDataHash
        self.credentialPublicKey = self.extractPubKey()

        # それぞれのattStmtの検証
        attStmt.validate(dataToVerify, self.credentialPublicKey)
