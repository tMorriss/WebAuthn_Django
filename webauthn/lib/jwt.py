import json

from webauthn.lib.exceptions import InvalidValueException
from webauthn.lib.utils import base64_url_decode


class JWT:
    def __init__(self, text):
        jwt = text.split('.')
        if len(jwt) != 3:
            raise InvalidValueException("jwt")

        self.header = json.loads(base64_url_decode(jwt[0]).decode())
        self.payload = json.loads(base64_url_decode(jwt[1]).decode())

        self.base64_header = jwt[0]
        self.base64_payload = jwt[1]
        self.signature = base64_url_decode(jwt[2])
