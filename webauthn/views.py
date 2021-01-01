from datetime import timedelta
from django.http import HttpResponse
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from webauthn.lib.attestationObject import AttestationObject
from webauthn.lib.clientData import ClientData
from webauthn.lib.exceptions import FormatException, InvalidValueException, UnsupportedException
from webauthn.lib.utils import generateId, stringToBase64Url, base64UrlDecode
from webauthn.lib.values import Values
from webauthn.models import Key, Session
from webauthn.lib.response import Response
from webauthn.lib.authData import AuthData
from webauthn.lib.publicKey import PublicKey
from Crypto.PublicKey import RSA
import json


def index(request):
    return render(request, 'index.html')


@csrf_exempt
def attestation_options(request):
    # POSTのみ受付
    if request.method != 'POST':
        return Response.formatError("http method")

    post_data = json.loads(request.body)

    if "username" not in post_data:
        return HttpResponse(Response.formatError("username"))
    username = post_data["username"]

    # 名前が長かったらエラー
    if len(username) > Values.USERNAME_MAX_LENGTH:
        return HttpResponse(Response.invalidValueError("username length"))

    challenge = generateId(Values.CHALLENGE_LENGTH)
    options = {
        "statusCode": Values.SUCCESS_CODE,
        "rp": {
            "id": Values.RP_ID,
            "name": "tmorriss.com"
        },
        "user": {
            "id": username,
            "name": username,
            "displayName": username
        },
        "challenge": challenge,
        "pubKeyCredParams": [],
        "timeout": Values.CREDENTIAL_TIMEOUT_MICROSECOND,
        "authenticatorSelection": {
            "authenticatorAttachment": "platform",
            "requireResidentKey": False,
            "userVerification": "preferred"
        },
        "attestation": "direct"
    }

    for alg in Values.ALG_LIST.values():
        options["pubKeyCredParams"].append({
            "type": "public-key",
            "alg": alg
        })

    # challengeの保存
    now = timezone.now()
    Session.objects.create(challenge=stringToBase64Url(challenge),
                           username=username, time=now, function="attestation")

    # 古いセッションを削除
    for s in Session.objects.all():
        if now > s.time + timedelta(minutes=Values.SESSION_TIMEOUT_MINUTE):
            s.delete()

    return HttpResponse(json.dumps(options))


@csrf_exempt
def attestation_result(request):
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
        if 'clientDataJSON' not in response:
            raise FormatException("response.clientDataJSON")
        if 'attestationObject' not in response:
            raise FormatException("response.attestationObject")

        # clientDataの読み込み
        clientData = ClientData(response['clientDataJSON'])
        # 検証
        clientData.validateCreate()
        # challenge取得
        challenge = clientData.challenge

        # AttestationObjectの読み込み
        try:
            attestationObject = AttestationObject(
                response['attestationObject'])
        except UnicodeDecodeError:
            raise FormatException("attestationObject")

        # authDataの検証
        attestationObject.authData.validate()

        # attStmtの検証
        attestationObject.validateAttStmt(clientData.hash)

        # すでに登録済みか確認
        if Key.objects.filter(credentialId=attestationObject.authData.credentialId).count() != 0:
            raise InvalidValueException("already registered")

        # challengeの確認
        session = Session.objects.filter(
            challenge=challenge, function="attestation")
        if session.count() != 1:
            raise InvalidValueException("clientDataJson.challenge")
        session = session.first()

        # 時刻確認
        now = timezone.now()
        if session.time >= now + timedelta(minutes=Values.SESSION_TIMEOUT_MINUTE):
            raise InvalidValueException("session timeout")

        # 名前を取り出す
        username = session.username

        # session削除
        session.delete()

        # 保存
        Key.objects.create(username=username, credentialId=attestationObject.authData.credentialId,
                           alg=attestationObject.alg,
                           credentialPublicKey=attestationObject.credentialPublicKey.export_key().decode('utf-8'),
                           signCount=attestationObject.authData.signCount, regTime=now)

    except FormatException as e:
        return HttpResponse(Response.formatError(str(e)))
    except InvalidValueException as e:
        return HttpResponse(Response.invalidValueError(str(e)))
    except UnsupportedException as e:
        return HttpResponse(Response.unsupportedError(str(e)))

    return HttpResponse(Response.success())


@csrf_exempt
def assertion_options(request):
    # POSTのみ受付
    if request.method != 'POST':
        return HttpResponse(Response.formatError("http method"))

    post_data = json.loads(request.body)

    if "username" not in post_data:
        return HttpResponse(Response.formatError("username"))
    username = post_data["username"]

    challenge = generateId(Values.CHALLENGE_LENGTH)
    options = {
        "statusCode": Values.SUCCESS_CODE,
        "challenge": challenge,
        "timeout": Values.CREDENTIAL_TIMEOUT_MICROSECOND,
        "rpId": Values.RP_ID,
        "allowCredentials": [],
        "userVerification": "required"
    }

    # AllowCredentials
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

        return HttpResponse(Response.success())

    except FormatException as e:
        return HttpResponse(Response.formatError(str(e)))
    except InvalidValueException as e:
        return HttpResponse(Response.invalidValueError(str(e)))
