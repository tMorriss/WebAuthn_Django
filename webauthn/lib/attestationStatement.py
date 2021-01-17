from abc import ABCMeta, abstractmethod
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA256
from datetime import datetime as dt
from webauthn.lib.certificate import Certificate
from webauthn.lib.exceptions import FormatException, InvalidValueException, UnsupportedException
from webauthn.lib.jwt import JWT
from webauthn.lib.publicKey import PublicKey
from webauthn.lib.utils import base64UrlDecode
from webauthn.lib.values import Values
import base64
import hashlib


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

    def validate(self, dataToVerify, pubKey):
        now = dt.now()

        # 証明書読み込み
        cert = x509.load_der_x509_certificate(
            base64UrlDecode(self.jwt.header["x5c"][0]))
        chain = x509.load_der_x509_certificate(
            base64UrlDecode(self.jwt.header["x5c"][1]))

        # 証明書検証
        Certificate.verify_chain(cert, chain, self.rootCertificates, now)

        # JWSの署名検証
        data = self.jwt.base64_header + '.' + self.jwt.base64_payload
        padding = None
        alg = None
        if self.jwt.header['alg'] == 'RS256':
            padding = PKCS1v15()
            alg = SHA256()

        try:
            cert.public_key().verify(self.jwt.signature, data.encode(),
                                     padding, alg)
        except InvalidSignature:
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
        self.rootCertificates = []

        for c in metadata.get_root_certificates():
            self.rootCertificates.append(
                x509.load_der_x509_certificate(base64.b64decode(c)))
