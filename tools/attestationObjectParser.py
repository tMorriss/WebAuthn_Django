import cbor2
import json
import sys

from os.path import dirname, abspath

sys.path.append(dirname(dirname(abspath(__file__))))
from webauthn.lib.authData import AuthData
from webauthn.lib.utils import base64_url_decode

if __name__ == '__main__':

    # print('input attestationObject')
    # line = input()
    line = ''

    cbor = cbor2.loads(base64_url_decode(line))
    auth_data = AuthData(cbor['authData'])
    result = {}
    result['fmt'] = cbor['fmt']
    result['attStmt'] = {
        'ver': cbor['attStmt']['ver'],
        'response': '...'
    }
    result['authData'] = {
        'up': auth_data.up,
        'uv': auth_data.uv,
        'sign_count': auth_data.sign_count,
        'aaguid': auth_data.aaguid,
        'backup_eligibility': auth_data.be,
        'backup_state': auth_data.bs,
    }

    print(json.dumps(result, indent=2))
