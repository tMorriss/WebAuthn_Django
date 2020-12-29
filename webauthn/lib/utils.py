import random
import string
import base64
# from secrets import token_bytes


def generateId(n):
    randlst = [random.choice(string.ascii_letters + string.digits)
               for i in range(n)]
    return ''.join(randlst)


def bytesToBase64Url(data):
    return base64.b64encode(data).decode().replace('+', '-').replace('/', '_').replace('=', '')


def stringToBase64Url(text):
    return base64.b64encode(text.encode()).decode().replace('+', '-').replace('/', '_').replace('=', '')


def base64UrlDecode(text):
    return base64.b64decode(text.replace('-', '+').replace('_', '/')+('=' * (len(text) % 4)))
