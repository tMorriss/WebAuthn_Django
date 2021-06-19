import base64
import random
import string


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
