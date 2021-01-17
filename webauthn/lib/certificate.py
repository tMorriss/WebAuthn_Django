from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from webauthn.lib.exceptions import InvalidValueException


class Certificate:
    @staticmethod
    def verify_chain(cert, chain, roots, now):
        # 証明書チェーン検証
        # 末端-中間
        if not Certificate.verify(chain.public_key(), cert):
            raise InvalidValueException("cert")
        # 中間-Root
        isValud = False
        for c in roots:
            if Certificate.verify(c.public_key(), chain):
                isValud = True
                # expire
                if c.not_valid_before > now or c.not_valid_after < now:
                    raise InvalidValueException("root cert expire")
        if not isValud:
            raise InvalidValueException("chain")

        # 証明書のexpire
        if cert.not_valid_before > now or cert.not_valid_after < now:
            raise InvalidValueException("cert.expire")
        if chain.not_valid_before > now or chain.not_valid_after < now:
            raise InvalidValueException("chain.expire")

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
