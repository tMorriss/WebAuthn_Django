import hashlib

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from ecdsa import VerifyingKey
from ecdsa.util import sigdecode_der
from webauthn.lib.exceptions import UnsupportedException
from webauthn.lib.values import Values


class PublicKey:
    @staticmethod
    def verify(pubKey, data, sig, alg):
        if alg == Values.ALG_LIST['RS256']:
            try:
                h = SHA256.new(data)
                k = RSA.import_key(pubKey)
                pkcs1_15.new(k).verify(h, sig)
                return True
            except ValueError:
                return False
        if alg == Values.ALG_LIST['ES256']:
            vk = vk = VerifyingKey.from_pem(
                pubKey, hashfunc=hashlib.sha256)
            return vk.verify(sig, data, sigdecode=sigdecode_der)
        else:
            raise UnsupportedException("alg=" + alg)
