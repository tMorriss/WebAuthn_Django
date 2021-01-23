import base64
import datetime
import hashlib
import json
import os

import requests
from webauthn.lib.exceptions import (InternalServerErrorException,
                                     InvalidValueException,
                                     UnsupportedException)
from webauthn.lib.jwt import JWT
from webauthn.lib.utils import bytesToBase64Url


class MetaDataService:

    def get(self, aaguid):
        self.__get_toc()
        self.__get_entry(aaguid)
        self.__get_metadata()

    def __get_toc(self):
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

    def __get_entry(self, aaguid):
        if 'entries' not in self.toc.payload:
            raise UnsupportedException("toc.entries")
        entries = self.toc.payload['entries']

        for e in entries:
            if 'aaguid' not in e:
                continue

            if e['aaguid'].replace('-', '') == aaguid:
                self.entry = e
                return

        raise UnsupportedException('metadata service entry is missing')

    def __get_metadata(self):
        r = requests.get(
            self.entry['url'],
            {"token": os.environ.get('METADATA_TOKEN')}
        )

        if r.status_code != 200:
            raise InternalServerErrorException("get metadata")

        base64Text = r.text
        self.metadata = json.loads(base64.b64decode(base64Text))

        # hash確認
        digest = hashlib.sha256(base64Text.encode()).digest()
        base64UrlDigest = bytesToBase64Url(digest)
        if self.entry['hash'] != base64UrlDigest:
            raise UnsupportedException('metadata.entry.hash')

        # statusの確認
        if 'statusReports' not in self.entry or len(self.entry['statusReports']) <= 0:
            raise UnsupportedException('metadata.entry.statusReports')
        effectiveDate = None
        status = None
        # 最新のstatus確認
        for r in self.entry['statusReports']:
            if 'status' not in r:
                raise UnsupportedException(
                    'metadata.entry.statusReports.status')
            if 'effectiveDate' not in r:
                raise UnsupportedException(
                    'metadata.entry.statusReports.effectiveDate')
            t = datetime.datetime.strptime(r['effectiveDate'], '%Y-%m-%d')
            d = datetime.date(t.year, t.month, t.day)
            if effectiveDate is None or effectiveDate < d:
                effectiveDate = d
                status = r['status']
        # 承認されているか確認
        if not status.startswith('FIDO_CERTIFIED'):
            raise UnsupportedException('not certified device in meta data')

    def get_root_certificates(self):
        return self.metadata['attestationRootCertificates']
