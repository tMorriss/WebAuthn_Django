from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15, DSS
from webauthn.lib.values import Values
from webauthn.lib.exceptions import UnsupportedException


class PublicKey:
    @staticmethod
    def verify(pubKey, data, sig, alg):
        if alg == Values.ALG_LIST['RS256']:
            try:
                h = SHA256.new(data)
                pkcs1_15.new(pubKey).verify(h, sig)
                return True
            except ValueError:
                return False
        if alg == Values.ALG_LIST['EC256']:
            try:
                h = SHA256.new(data)
                DSS.new(pubKey).verify(h, sig)
                return True
            except ValueError:
                return False
        else:
            raise UnsupportedException("alg=" + alg)
