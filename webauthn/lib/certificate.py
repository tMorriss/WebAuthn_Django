from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15


class Certificate:
    @staticmethod
    def verify(key, cert):
        padding = None
        if cert.signature_algorithm_oid._name == 'sha256WithRSAEncryption':
            padding = PKCS1v15()
        try:
            key.verify(
                cert.signature, cert.tbs_certificate_bytes, padding, cert.signature_hash_algorithm)
            return True
        except InvalidSignature:
            return False
        except TypeError:
            return False
