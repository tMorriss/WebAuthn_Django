import requests
from webauthn.lib.exceptions import InternalServerErrorException


class AuthenticatorInformation:
    def __init__(self):
        r = requests.get("https://raw.githubusercontent.com/passkeydeveloper/passkey-authenticator-aaguids/main/aaguid.json")

        if r.status_code != 200:
            raise InternalServerErrorException("get blob")

        self.informations = r.json()

    def get(self, aaguid):
        for k in self.informations.keys():
            if k.replace('-', '') == aaguid:
                return self.informations[k]
