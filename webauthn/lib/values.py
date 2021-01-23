import os


class Values:
    RP_ID = os.environ.get('RP_ID', 'localhost')
    ORIGIN = "https://" + os.environ.get('RP_ID', 'localhost:8000')

    ALG_LIST = {'RS256': -257, 'ES256': -7}
    KTY_LIST = {'EC2': 2, 'RSA': 3}
    EC_KEYS = {1: 'P-256', 2: 'P-384', 3: 'P-521',
               4: 'X25519', 5: 'X448', 6: 'Ed25519', 7: 'Ed448'}

    SIGN_COUNT_IGNORE_LIST = ['apple']

    CHALLENGE_LENGTH = 16
    USERNAME_MAX_LENGTH = 30
    SESSION_TIMEOUT_MINUTE = 5
    CREDENTIAL_TIMEOUT_MICROSECOND = 30000
    CREDENTIAL_VERIFY_TIMEOUT_SECONDS = 60

    SUCCESS_CODE = "2000"

    USERNAME = "username"
