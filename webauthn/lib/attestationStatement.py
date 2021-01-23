from abc import ABCMeta, abstractmethod
from datetime import datetime as dt
from webauthn.lib.certificate import Certificate
from webauthn.lib.exceptions import FormatException, InvalidValueException, UnsupportedException
from webauthn.lib.exceptions import InternalServerErrorException
from webauthn.lib.jwt import JWT
from webauthn.lib.publicKey import PublicKey
from webauthn.lib.utils import base64UrlDecode
from webauthn.lib.values import Values
import base64
import hashlib
import requests


class AttestationStatement(metaclass=ABCMeta):
    @abstractmethod
    def __init__(self, attStmt):
        raise NotImplementedError()

    @abstractmethod
    def validate(self, dataToVerify, pubKey):
        raise NotImplementedError()


class Packed(AttestationStatement):
    def __init__(self, attStmt):
        # validate
        if 'alg' not in attStmt:
            raise FormatException('attStmt.alg')
        if 'sig' not in attStmt:
            raise FormatException('attStmt.sig')

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


class AndroidSafetyNet(AttestationStatement):
    def __init__(self, attStmt):
        # validate
        if 'ver' not in attStmt:
            raise FormatException('attStmt.ver')
        if 'response' not in attStmt:
            raise FormatException('attStmt.response')

        response = attStmt['response'].decode()

        try:
            self.jwt = JWT(response)
        except InvalidValueException:
            raise InvalidValueException("attStmt.response")

        self.cert = Certificate()

    def validate(self, dataToVerify, pubKey):
        now = dt.now()

        # 証明書読み込み
        self.cert.set_cert_der(base64UrlDecode(self.jwt.header["x5c"][0]))
        self.cert.set_chain_der(base64UrlDecode(self.jwt.header["x5c"][1]))

        # 証明書検証
        self.cert.verify_chain(now)

        # JWSの署名検証
        data = (self.jwt.base64_header + '.' +
                self.jwt.base64_payload).encode()

        if not PublicKey.verify(
            self.cert.get_cert_pubkey_pem(),
            data,
            self.jwt.signature,
            Values.ALG_LIST[self.jwt.header['alg']]
        ):
            raise InvalidValueException(
                "attStmt.response jwt signature")

        # timestampMs
        if 'timestampMs' not in self.jwt.payload.keys() or \
            (now - dt.fromtimestamp(int(self.jwt.payload['timestampMs']) / 1000)).total_seconds() > \
                Values.CREDENTIAL_VERIFY_TIMEOUT_SECONDS:
            raise InvalidValueException(
                "attStmt.response.timestampMs (" + self.jwt.payload['timestampMs'] + ")")

        # nonce
        nonceBuffer = hashlib.sha256(dataToVerify).digest()
        expectedNonce = base64.b64encode(nonceBuffer).decode()
        if 'nonce' not in self.jwt.payload.keys() or self.jwt.payload['nonce'] != expectedNonce:
            raise InvalidValueException("attStmt.response.nonce")

        # ctsProfileMatch
        if 'ctsProfileMatch' not in self.jwt.payload.keys() or not self.jwt.payload['ctsProfileMatch']:
            raise InvalidValueException("attStmt.response.ctsProfileMatch")

        # basicIntegrity
        if 'basicIntegrity' not in self.jwt.payload.keys() or not self.jwt.payload['basicIntegrity']:
            raise InvalidValueException("attStmt.response.basicIntegrity")

    def add_root_certificate(self, metadata):
        for c in metadata.get_root_certificates():
            self.cert.add_root_der(base64.b64decode(c))


class Apple(AttestationStatement):
    def __init__(self, attStmt):
        # validate
        if 'x5c' not in attStmt:
            raise FormatException('attStmt.x5c')

        self.attStmt = attStmt
        self.cert = Certificate()

    def validate(self, dataToVerify, pubKey):
        now = dt.now()

        # 証明書読み込み
        self.cert.set_cert_der(self.attStmt["x5c"][0])
        self.cert.set_chain_der(self.attStmt["x5c"][1])

        # 1.2.840.113635.100.8.2読み込み
        nonce = self.cert.get_extension('1.2.840.113635.100.8.2')
        # nonce比較
        expect = hashlib.sha256(dataToVerify).digest()
        if nonce[6:] != expect:
            raise InvalidValueException('attStmt.x5c.extension')

        # 公開鍵比較
        cert_pubkey = self.cert.get_cert_pubkey_pem()
        if pubKey.replace('\n', '') != cert_pubkey.replace('\n', ''):
            raise InvalidValueException('attStmt.x5c.chain.pubkey')

        # 証明書検証
        self.cert.add_root_pem(self.__get_apple_root_cert())
        self.cert.verify_chain(now)

    def __get_apple_root_cert(self):
        r = requests.get(
            "https://www.apple.com/certificateauthority/Apple_WebAuthn_Root_CA.pem"
        )

        if r.status_code != 200:
            raise InternalServerErrorException("get apple root cert")

        return r.text
