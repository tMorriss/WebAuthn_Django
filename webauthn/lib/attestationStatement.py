import base64
import hashlib
from abc import ABCMeta, abstractmethod
from datetime import datetime as dt

import cbor2
import requests
from webauthn.lib.certificate import Certificate
from webauthn.lib.exceptions import (FormatException,
                                     InternalServerErrorException,
                                     InvalidValueException,
                                     UnsupportedException)
from webauthn.lib.jwt import JWT
from webauthn.lib.publicKey import PublicKey
from webauthn.lib.utils import base64_url_decode, get_hash
from webauthn.lib.values import Values


class AttestationStatement(metaclass=ABCMeta):
    @abstractmethod
    def __init__(self, att_stmt):
        raise NotImplementedError()

    @abstractmethod
    def validate(self, data_to_verify, pub_key):
        raise NotImplementedError()


class Packed(AttestationStatement):
    def __init__(self, att_stmt):
        # validate
        if 'alg' not in att_stmt:
            raise FormatException('attStmt.alg')
        if 'sig' not in att_stmt:
            raise FormatException('attStmt.sig')

        self.att_stmt = att_stmt
        self.alg = att_stmt['alg']

    def validate(self, data_to_verify, pub_key):
        # algが対応していることの確認
        if self.alg not in Values.ALG_LIST.values():
            raise UnsupportedException('AttestationStatemtnt.alg')

        if "x5c" not in self.att_stmt:
            if not PublicKey.verify(pub_key, data_to_verify,
                                    self.att_stmt['sig'], self.alg):
                raise InvalidValueException("attStmt.sig")
        else:
            raise UnsupportedException("packed with x5c")


class AndroidSafetyNet(AttestationStatement):
    def __init__(self, att_stmt):
        # validate
        if 'ver' not in att_stmt:
            raise FormatException('attStmt.ver')
        if 'response' not in att_stmt:
            raise FormatException('attStmt.response')

        response = att_stmt['response'].decode()

        try:
            self.jwt = JWT(response)
        except InvalidValueException:
            raise InvalidValueException("attStmt.response")

        self.cert = Certificate()

    def validate(self, data_to_verify, pubKey):
        now = dt.now()

        # 証明書読み込み
        self.cert.set_cert_der(base64_url_decode(self.jwt.header["x5c"][0]))
        self.cert.set_chain_der(base64_url_decode(self.jwt.header["x5c"][1]))

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
        nonce_buffer = hashlib.sha256(data_to_verify).digest()
        expected_nonce = base64.b64encode(nonce_buffer).decode()
        if 'nonce' not in self.jwt.payload.keys() or self.jwt.payload['nonce'] != expected_nonce:
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
    def __init__(self, att_stmt):
        # validate
        if 'x5c' not in att_stmt:
            raise FormatException('attStmt.x5c')

        self.att_stmt = att_stmt
        self.cert = Certificate()

    def validate(self, data_to_verify, pub_key):
        now = dt.now()

        # 証明書読み込み
        self.cert.set_cert_der(self.att_stmt["x5c"][0])
        self.cert.set_chain_der(self.att_stmt["x5c"][1])

        # 1.2.840.113635.100.8.2読み込み
        nonce = self.cert.get_extension('1.2.840.113635.100.8.2')
        # nonce比較
        expect = hashlib.sha256(data_to_verify).digest()
        if nonce[6:] != expect:
            raise InvalidValueException('att_stmt.x5c.extension')

        # 公開鍵比較
        cert_pubkey = self.cert.get_cert_pubkey_pem()
        if pub_key.replace('\n', '') != cert_pubkey.replace('\n', ''):
            raise InvalidValueException('att_stmt.x5c.chain.pubkey')

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


class Tpm(AttestationStatement):
    def __init__(self, att_stmt):
        # validate
        if 'ver' not in att_stmt:
            raise FormatException('attStmt.ver')
        self.ver = att_stmt['ver']
        if 'alg' not in att_stmt:
            raise FormatException('attStmt.alg')
        self.alg = att_stmt['alg']
        if 'x5c' not in att_stmt:
            raise FormatException('attStmt.x5c')
        self.x5c = att_stmt['x5c']
        if 'sig' not in att_stmt:
            raise FormatException('attStmt.sig')
        self.sig = att_stmt['sig']
        if 'certInfo' not in att_stmt:
            raise FormatException('attStmt.certInfo')
        self.cert_info = att_stmt['certInfo']
        if 'pubArea' not in att_stmt:
            raise FormatException('attStmt.pubArea')
        self.pub_area = att_stmt['pubArea']

    def validate(self, att_to_be_signed, pub_key):
        if self.ver != '2.0':
            raise InvalidValueException('attStmt.ver=' + self.ver)
        # algが対応していることの確認
        if self.alg not in Values.ALG_LIST.values():
            raise UnsupportedException('AttestationStatemtnt.alg=' + str(self.alg))

        # certInfoの中身を取り出す
        cert_info = self.cert_info

        cert_info_magic = cert_info[:4]
        cert_info = cert_info[4:]

        cert_info_type = cert_info[:2]
        cert_info = cert_info[2:]

        size = int.from_bytes(cert_info[:2], byteorder='big')
        cert_info = cert_info[size + 2:]

        size = int.from_bytes(cert_info[:2], byteorder='big')
        cert_info = cert_info[2:]

        cert_info_extra_data = cert_info[:size]
        cert_info = cert_info[size:]

        cert_info = cert_info[25:]

        size = int.from_bytes(cert_info[:2], byteorder='big')
        cert_info = cert_info[2:]

        cert_info_attested_certify_name = cert_info[:size]

        # pubAreaの中身を取り出す
        pub_area = self.pub_area

        pub_area_type = pub_area[:2]
        pub_area = pub_area[2:]

        pub_area_name_alg = pub_area[:2]
        pub_area = pub_area[2:]

        # Verify that magic is set to TPM_GENERATED_VALUE.
        if cert_info_magic != Values.TPM_GENERATED_VALUE:
            raise InvalidValueException('AttestationStatement.certInfo.magic')

        # Verify that type is set to TPM_ST_ATTEST_CERTIFY.
        if cert_info_type != Values.TPM_ST_ATTEST_CERTIFY:
            raise InvalidValueException('AttestationStatement.certInfo.type')

        # Verify that extraData is set to the hash of attToBeSigned using the hash algorithm employed in "alg".
        if cert_info_extra_data != get_hash(att_to_be_signed, self.alg):
            raise InvalidValueException('AttestationStatement.certInfo.extraData')

        # Verify attested
        expected_name = None
        if pub_area_name_alg == b'\x00\x0b':
            expected_name = pub_area_name_alg + hashlib.sha256(self.pub_area).digest()

        if cert_info_attested_certify_name != expected_name:
            raise InvalidValueException('AttestationStatement.certInfo.attested.certify.name or AttestationStatement.pubArea.nameAlg')

        # 証明書読み込み
        cert = Certificate()
        cert.set_cert_der(self.x5c[0])
        cert.set_chain_der(self.x5c[1])

        # Verify the sig is a valid signature over certInfo using the attestation public key in aikCert with the algorithm specified in alg.
        if not PublicKey.verify(cert.get_cert_pubkey_pem(), self.cert_info, self.sig, self.alg):
            raise InvalidValueException('AttestationStatement.sig')

        # Version MUST be set to 3.
        if not cert.is_cert_ver_3:
            raise InvalidValueException('AttestationStatement.aikCert.Version')

        # Subject field MUST be set to empty.
        if cert.get_cert_subject() != '':
            raise InvalidValueException('AttestationStatement.aikCert.Subject')

        san = cert.get_subject_alternative_name()
        print(san[0])
        print(type(san[0]))
        print(san[0].get_attributes_for_oid('2.23.133.2.1'))

        # for e in cert.cert.extensions:
        #     print(e.oid)
        # print(base64.b64encode(self.x5c[0]))
