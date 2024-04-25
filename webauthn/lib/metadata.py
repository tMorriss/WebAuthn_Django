import datetime

import requests
from webauthn.lib.exceptions import (InternalServerErrorException,
                                     InvalidValueException,
                                     UnsupportedException)
from webauthn.lib.jwt import JWT


class MetaDataService:

    def get(self, aaguid):
        self.__get_blob()
        self.__get_metadata(aaguid)
        self.__verify_metadata()

    def __get_blob(self):
        r = requests.get("https://mds.fidoalliance.org/")

        if r.status_code != 200:
            raise InternalServerErrorException("get blob")

        try:
            self.blob = JWT(r.text)
        except InvalidValueException:
            raise InternalServerErrorException("blob format")

    def __get_metadata(self, aaguid):
        if 'entries' not in self.blob.payload:
            raise UnsupportedException("blob.entries")
        entries = self.blob.payload['entries']

        for e in entries:
            if 'aaguid' not in e:
                continue

            if e['aaguid'].replace('-', '') == aaguid:
                self.metadata = e
                return

        raise UnsupportedException('metadata service data is missing')

    def __verify_metadata(self):
        # statusの確認
        if 'statusReports' not in self.metadata or len(self.metadata['statusReports']) <= 0:
            raise UnsupportedException('metadata.metadata.statusReports')
        effective_date = None
        status = None
        # 最新のstatus確認
        for r in self.metadata['statusReports']:
            if 'status' not in r:
                raise UnsupportedException(
                    'metadata.metadata.statusReports.status')
            if 'effectiveDate' not in r:
                raise UnsupportedException(
                    'metadata.metadata.statusReports.effectiveDate')
            t = datetime.datetime.strptime(r['effectiveDate'], '%Y-%m-%d')
            d = datetime.date(t.year, t.month, t.day)
            if effective_date is None or effective_date < d:
                effective_date = d
                status = r['status']
        # 承認されているか確認
        if not status.startswith('FIDO_CERTIFIED'):
            raise UnsupportedException('not certified device in meta data: ' + status)

    def get_root_certificates(self):
        return self.metadata['metadataStatement']['attestationRootCertificates']
