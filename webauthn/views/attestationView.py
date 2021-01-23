import hashlib
import json
from datetime import timedelta

from django.http import HttpResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from webauthn.lib.attestationObject import AttestationObject
from webauthn.lib.clientData import ClientData
from webauthn.lib.exceptions import (FormatException,
                                     InternalServerErrorException,
                                     InvalidValueException,
                                     UnsupportedException)
from webauthn.lib.response import Response
from webauthn.lib.utils import generateId, stringToBase64Url
from webauthn.lib.values import Values
from webauthn.models import Key, Session, User


@csrf_exempt
def attestation_options(request):
    # POSTのみ受付
    if request.method != 'POST':
        return Response.formatError("http method")

    post_data = json.loads(request.body)

    if "username" not in post_data:
        return HttpResponse(Response.formatError("username"))
    username = post_data["username"]
    userid = hashlib.sha256(username.encode('utf-8')).hexdigest()

    # 名前が長かったらエラー
    if len(username) > Values.USERNAME_MAX_LENGTH:
        return HttpResponse(Response.invalidValueError("username length"))
    # 名前が空だったらエラー
    if len(username) < 1:
        return HttpResponse(Response.invalidValueError("empty username"))

    # ユーザがいなかったら作成
    users = User.objects.filter(name=username)
    if users.count() <= 0:
        user = User.objects.create(name=username, uid=userid)
    else:
        user = users.first()

    challenge = generateId(Values.CHALLENGE_LENGTH)
    options = {
        "statusCode": Values.SUCCESS_CODE,
        "rp": {
            "id": Values.RP_ID,
            "name": Values.RP_ID
        },
        "user": {
            "id": user.uid,
            "name": user.name,
            "displayName": user.name
        },
        "challenge": challenge,
        "pubKeyCredParams": [],
        "timeout": Values.CREDENTIAL_TIMEOUT_MICROSECOND,
        "excludeCredentials": [],
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

    # excludeCredentials
    excludeCredentials = Key.objects.filter(user=user)
    for c in excludeCredentials:
        options["excludeCredentials"].append({
            "type": "public-key",
            "id": c.credentialId,
            "transports": ["internal"]
        })

    # challengeの保存
    now = timezone.now()
    Session.objects.create(challenge=stringToBase64Url(challenge),
                           user=user, time=now, function="attestation")

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
        if 'transports' not in response:
            raise FormatException("response.transports")

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

        # session削除
        session.delete()

        # 保存
        Key.objects.create(
            user=session.user,
            credentialId=attestationObject.authData.credentialId,
            aaguid=attestationObject.authData.aaguid,
            alg=attestationObject.alg,
            fmt=attestationObject.fmt,
            credentialPublicKey=attestationObject.credentialPublicKey,
            signCount=attestationObject.authData.signCount,
            transports=json.dumps(response['transports']),
            regTime=now
        )

        return HttpResponse(Response.success({'username': session.user.name}))
    except FormatException as e:
        return HttpResponse(Response.formatError(str(e)))
    except InvalidValueException as e:
        return HttpResponse(Response.invalidValueError(str(e)))
    except UnsupportedException as e:
        return HttpResponse(Response.unsupportedError(str(e)))
    except InternalServerErrorException as e:
        return HttpResponse(Response.internalServerError(str(e)))
