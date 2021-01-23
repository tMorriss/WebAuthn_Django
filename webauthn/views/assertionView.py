from django.http import HttpResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from webauthn.lib.clientData import ClientData
from webauthn.lib.exceptions import FormatException, InvalidValueException
from webauthn.lib.utils import generateId, stringToBase64Url, base64UrlDecode
from webauthn.lib.values import Values
from webauthn.models import User, Key, Session
from webauthn.lib.response import Response
from webauthn.lib.authData import AuthData
from webauthn.lib.publicKey import PublicKey
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
    user = None

    # 名前が渡ってきたときはallowCredentialsを入れる
    # 指定されていないときはresidentKey
    if "username" in post_data:
        username = post_data['username']

        # ユーザの存在確認
        users = User.objects.filter(name=username)
        if users.count() <= 0:
            raise InvalidValueException('username')

        user = users.first()
        credentials = Key.objects.filter(user=users.first())
        for c in credentials:
            options['allowCredentials'].append({
                "type": "public-key",
                "id": c.credentialId,
                "transports": json.loads(c.transports)
            })

    # challengeの保存
    now = timezone.now()
    Session.objects.create(challenge=stringToBase64Url(challenge),
                           user=user, time=now, function="assertion")

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
        # credentialId読み込み
        if 'id' not in post_data:
            raise FormatException("id")

        # validate
        if 'authenticatorData' not in response:
            raise FormatException("response.authenticatorData")
        if 'clientDataJSON' not in response:
            raise FormatException("response.clientDataJSON")
        if 'signature' not in response:
            raise FormatException("response.signature")

        # clientDataの読み込み
        clientData = ClientData(response['clientDataJSON'])
        # 検証
        clientData.validateGet()
        # challenge取得
        challenge = clientData.challenge

        # challengeの確認
        sessions = Session.objects.filter(
            challenge=challenge, function="assertion")
        if sessions.count() != 1:
            raise InvalidValueException("clientDataJson.challenge")
        session = sessions.first()

        # userの取得
        user = None
        if 'userHandle' in response and len(response['userHandle']) > 0:
            userid = response['userHandle']
            users = User.objects.filter(uid=userid)
            if users.count() < 1:
                raise InvalidValueException('response.userHandle is not exist')
            user = users.first()
            if session.user is not None and user.uid != session.user.uid:
                raise InvalidValueException('response.userHandle is not match')
        else:
            user = session.user

        # authenticatorDataの検証
        authData = AuthData(base64UrlDecode(response['authenticatorData']))
        authData.validate()

        # 公開鍵の検証
        pubKeys = Key.objects.filter(
            user=user, credentialId=post_data['id'])
        if len(pubKeys) != 1:
            raise InvalidValueException('public key is missing')
        pubKey = pubKeys[0]
        dataToVerify = authData.authData + clientData.hash
        if not PublicKey.verify(
                pubKey.credentialPublicKey,
                dataToVerify,
                base64UrlDecode(response['signature']),
                pubKey.alg):
            raise InvalidValueException('response.signature')

        # signCountの検証
        if pubKey.fmt not in Values.SIGN_COUNT_IGNORE_LIST and pubKey.signCount >= authData.signCount:
            raise InvalidValueException('signCount')

        # signCountの更新
        pubKey.signCount = authData.signCount
        pubKey.save()

        return HttpResponse(Response.success({'username': pubKey.user.name}))

    except FormatException as e:
        return HttpResponse(Response.formatError(str(e)))
    except InvalidValueException as e:
        return HttpResponse(Response.invalidValueError(str(e)))
