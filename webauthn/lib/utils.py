import base64
import hashlib
import random
import string

from webauthn.lib.values import Values


def generate_id(n):
    randlst = [random.choice(string.ascii_letters + string.digits)
               for i in range(n)]
    return ''.join(randlst)


def bytes_to_base64_url(data):
    return base64.b64encode(data).decode().replace('+', '-').replace('/', '_').replace('=', '')


def string_to_base64_url(text):
    return base64.b64encode(text.encode()).decode().replace('+', '-').replace('/', '_').replace('=', '')


def base64_url_decode(text):
    return base64.b64decode(text.replace('-', '+').replace('_', '/') + ('=' * (4 - len(text) % 4)))


def get_hash(data, alg):
    if alg == Values.ALG_LIST['RS1']:
        return hashlib.sha1(data).digest()
