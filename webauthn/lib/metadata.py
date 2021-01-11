from webauthn.lib.exceptions import InvalidValueException, InternalServerErrorException
from webauthn.lib.jwt import JWT
import base64
import json
import os
import requests


class MetaDataService:
    def get_toc(self):
        r = requests.get(
            "https://mds2.fidoalliance.org/",
            {"token": os.environ.get('METADATA_TOKEN')}
        )

        if r.status_code != 200:
            raise InternalServerErrorException("get toc")

        try:
            self.toc = JWT(r.text)
        except InvalidValueException:
            raise InternalServerErrorException("toc format")

    def get_entry(self, aaguid):
        if 'entries' not in self.toc.payload:
            raise InternalServerErrorException("toc.entries")
        entries = self.toc.payload['entries']

        for e in entries:
            if 'aaguid' not in e:
                continue

            if e['aaguid'].replace('-', '') == aaguid:
                self.entry = e

    def get_metadata(self):
        r = requests.get(
            self.entry['url'],
            {"token": os.environ.get('METADATA_TOKEN')}
        )

        if r.status_code != 200:
            raise InternalServerErrorException("get metadata")

        self.metadata = json.loads(base64.b64decode(r.text))

    def get_root_certificates(self):
        return self.metadata['attestationRootCertificates']
