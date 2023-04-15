import json
import sys

from os.path import dirname, abspath

sys.path.append(dirname(dirname(abspath(__file__))))
from webauthn.lib.utils import base64_url_decode

if __name__ == '__main__':

    # print('input attestationObject')
    # line = input()
    line = ''

    client_data_json = base64_url_decode(line).decode('utf-8')
    client_data = json.loads(client_data_json)
    print(json.dumps(client_data, indent=2))
