import base64
import json
import requests


def base64_url_decode(text):
    return base64.b64decode(text.replace('-', '+').replace('_', '/') + ('=' * (4 - len(text) % 4)))


if __name__ == '__main__':
    r = requests.get("https://mds.fidoalliance.org/")

    if r.status_code != 200:
        raise Exception("get blob")

    jwt = r.text.split('.')

    payload = json.loads(base64_url_decode(jwt[1]).decode())

    print(json.dumps(payload, indent=2))
