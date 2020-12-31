from datetime import timedelta
from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from webauthn.lib.attestationObject import AttestationObject
from webauthn.lib.clientData import ClientData
from webauthn.lib.exceptions import FormatException, InvalidValueException, UnsupportedException
from webauthn.lib.utils import generateId, stringToBase64Url
from webauthn.lib.values import Values
from webauthn.models import Key, Session
import json


def index(request):
    return render(request, 'index.html')


@csrf_exempt
def attestation_options(request):
    # POSTのみ受付
    if request.method != 'POST':
        return "error"

    post_data = json.loads(request.body)

    if "username" not in post_data:
        return HttpResponseBadRequest(json.dumps({"status": "error"}))
    username = post_data["username"]

    # 名前が長かったらエラー
    if len(username) > Values.USERNAME_MAX_LENGTH:
        return HttpResponseBadRequest("Invalid Value (username length)")

    challenge = generateId(Values.CHALLENGE_LENGTH)
    options = {
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
        "timeout": 30000,
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
                           username=username, time=now)

    # 古いセッションを削除
    for s in Session.objects.all():
        if now > s.time + timedelta(minutes=Values.SESSION_TIMEOUT_MINUTE):
            s.delete()

    return HttpResponse(json.dumps(options))


@csrf_exempt
def attestation_result(request):
    # POSTのみ受付
    if request.method != 'POST':
        return "error"

    post_data = json.loads(request.body)

    # response読み込み
    if 'response' not in post_data:
        return 'parameter error (response)'
    response = post_data['response']

    # validate
    if 'clientDataJSON' not in response:
        return 'parameter error (clientDataJSON)'
    if 'attestationObject' not in response:
        return 'parameter error (attestationObject)'

    try:
        # clientDataの読み込み
        clientData = ClientData(response['clientDataJSON'])
        # 検証
        clientData.validate()
        # challenge取得
        challenge = clientData.challenge

        # AttestationObjectの読み込み
        try:
            attestationObject = AttestationObject(
                response['attestationObject'])
        except UnicodeDecodeError:
            raise FormatException("attestationObject")

        # AttestationObjectの検証
        attestationObject.validate()

        # attStmtの検証
        attestationObject.validateAttStmt(clientData.hash)

        # すでに登録済みか確認
        if Key.objects.filter(credentialId=attestationObject.credentialId).count() != 0:
            raise InvalidValueException("already registered")

        # challengeの確認
        session = Session.objects.filter(challenge=challenge)
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
        Key.objects.create(username=username, credentialId=attestationObject.credentialId,
                           credentialPublicKey=attestationObject.credentialPublicKey,
                           signCount=attestationObject.signCount, regTime=now)

    except FormatException as e:
        return HttpResponseBadRequest("Format Error (" + str(e) + ")")
    except InvalidValueException as e:
        return HttpResponseBadRequest("Invalid Value (" + str(e) + ")")
    except UnsupportedException as e:
        return HttpResponseBadRequest("Unsupported (" + str(e) + ")")

    return HttpResponse("success")
