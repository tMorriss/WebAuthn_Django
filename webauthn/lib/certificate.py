from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA256, SHA384
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import ObjectIdentifier, ExtensionNotFound
from webauthn.lib.exceptions import InvalidValueException, UnsupportedException
import base64


class Certificate:
    roots = []

    def set_cert_der(self, der):
        self.cert = x509.load_der_x509_certificate(der)

    def set_chain_der(self, der):
        self.chain = x509.load_der_x509_certificate(der)

    def add_root_der(self, der):
        self.roots.append(x509.load_der_x509_certificate(der))

    def add_root_pem(self, pem):
        pem = pem.replace('-----BEGIN CERTIFICATE-----', '')
        pem = pem.replace('-----END CERTIFICATE-----', '')
        b64 = pem.replace('\n', '')
        der = base64.b64decode(b64)
        self.add_root_der(der)

    def get_cert_pubkey_pem(self):
        return self.cert.public_key().public_bytes(encoding=Encoding.PEM,
                                                   format=PublicFormat.SubjectPublicKeyInfo).decode()

    def get_extension(self, oid):
        try:
            return self.cert.extensions.get_extension_for_oid(
                ObjectIdentifier(oid)).value.value
        except ExtensionNotFound:
            raise InvalidValueException('cert.extension')

    def verify_chain(self, now):
        # 末端-中間
        if not Certificate.verify(self.chain.public_key(), self.cert):
            raise InvalidValueException("cert")
        # 中間-Root
        isValud = False
        for c in self.roots:
            if Certificate.verify(c.public_key(), self.chain):
                isValud = True
                # expire
                if c.not_valid_before > now or c.not_valid_after < now:
                    raise InvalidValueException("root cert expire")
        if not isValud:
            raise InvalidValueException("chain")

        # 証明書のexpire
        if self.cert.not_valid_before > now or self.cert.not_valid_after < now:
            raise InvalidValueException("cert.expire")
        if self.chain.not_valid_before > now or self.chain.not_valid_after < now:
            raise InvalidValueException("chain.expire")

    @ staticmethod
    def verify(key, cert):
        try:
            if cert.signature_algorithm_oid._name == 'sha256WithRSAEncryption':
                key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    PKCS1v15(),
                    cert.signature_hash_algorithm
                )
                return True
            elif cert.signature_algorithm_oid._name == 'ecdsa-with-SHA256':
                key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    ECDSA(SHA256())
                )
                return True
            elif cert.signature_algorithm_oid._name == 'ecdsa-with-SHA384':
                key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    ECDSA(SHA384())
                )
                return True
            else:
                raise UnsupportedException(
                    'cert alg=' + cert.signature_algorithm_oid._name)
        except InvalidSignature:
            return False
        except TypeError:
            return False
