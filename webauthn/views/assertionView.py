from django.http import HttpResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from webauthn.lib.clientData import ClientData
from webauthn.lib.exceptions import FormatException, InvalidValueException
from webauthn.lib.utils import generateId, stringToBase64Url, base64UrlDecode
from webauthn.lib.values import Values
from webauthn.models import Key, Session
from webauthn.lib.response import Response
from webauthn.lib.authData import AuthData
from webauthn.lib.publicKey import PublicKey
from Crypto.PublicKey import RSA
import json


@csrf_exempt
def assertion_options(request):
    # POSTのみ受付
    if request.method != 'POST':
        return HttpResponse(Response.formatError("http method"))

    post_data = json.loads(request.body)

    challenge = generateId(Values.CHALLENGE_LENGTH)
    options = {
        "statusCode": Values.SUCCESS_CODE,
        "challenge": challenge,
        "timeout": Values.CREDENTIAL_TIMEOUT_MICROSECOND,
        "rpId": Values.RP_ID,
        "allowCredentials": [],
        "userVerification": "required"
    }

    username = ""

    # 名前がときはallowCredentialsを入れる
    # 指定されていないときはresidentKey
    if "username" in post_data:
        username = post_data['username']
        credentials = Key.objects.filter(username=username)
        for c in credentials:
            options['allowCredentials'].append({
                "type": "public-key",
                "id": c.credentialId,
                "transports": ["internal"]
            })

    # challengeの保存
    now = timezone.now()
    Session.objects.create(challenge=stringToBase64Url(challenge),
                           username=username, time=now, function="assertion")

    return HttpResponse(json.dumps(options))


@csrf_exempt
def assertion_result(request):
    try:
        # POSTのみ受付
        if request.method != 'POST':
            raise FormatException("http method")

        post_data = json.loads(request.body)

        # response読み込み
        if 'response' not in post_data:
            raise FormatException("response")
        response = post_data['response']

        # validate
        if 'authenticatorData' not in response:
            raise FormatException("response.authenticatorData")
        if 'clientDataJSON' not in response:
            raise FormatException("response.clientDataJSON")
        if 'signature' not in response:
            raise FormatException("response.signature")
        if 'userHandle' not in response:
            raise FormatException("response.userHandle")

        # username確認
        username = response['userHandle']
        credentials = Key.objects.filter(username=username)
        if credentials.count() < 1:
            raise InvalidValueException('response.userHandle')

        # credentialIdの確認
        if 'id' not in post_data:
            raise FormatException("id")
        isExist = False
        for c in credentials:
            if c.credentialId == post_data['id']:
                isExist = True
        if not isExist:
            raise InvalidValueException("id")

        # clientDataの読み込み
        clientData = ClientData(response['clientDataJSON'])
        # 検証
        clientData.validateGet()
        # challenge取得
        challenge = clientData.challenge

        # challengeの確認
        session = Session.objects.filter(
            challenge=challenge, function="assertion")
        if session.count() != 1:
            raise InvalidValueException("clientDataJson.challenge")
        session = session.first()

        # authenticatorDataの検証
        authData = AuthData(base64UrlDecode(response['authenticatorData']))
        authData.validate()

        # 公開鍵の検証
        pubKey = Key.objects.filter(credentialId=post_data['id'])[0]
        dataToVerify = authData.authData + clientData.hash
        if not PublicKey.verify(
                RSA.import_key(pubKey.credentialPublicKey),
                dataToVerify,
                base64UrlDecode(response['signature']),
                pubKey.alg):
            raise InvalidValueException('response.signature')

        # signCountの検証
        if pubKey.signCount >= authData.signCount:
            raise InvalidValueException('signCount')

        # signCountの更新
        pubKey.signCount = authData.signCount
        pubKey.save()

        return HttpResponse(Response.success(username))

    except FormatException as e:
        return HttpResponse(Response.formatError(str(e)))
    except InvalidValueException as e:
        return HttpResponse(Response.invalidValueError(str(e)))
