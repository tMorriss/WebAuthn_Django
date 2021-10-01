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
from webauthn.lib.utils import generate_id, string_to_base64_url
from webauthn.lib.values import Values
from webauthn.models import Key, RemoteSession, Session, User


@csrf_exempt
def attestation_options(request):
    # POSTのみ受付
    if request.method != 'POST':
        return Response.format_error("http method")

    post_data = json.loads(request.body)

    if "username" not in post_data:
        return HttpResponse(Response.format_error("username"))
    username = post_data["username"]
    userid = hashlib.sha256(username.encode('utf-8')).hexdigest()

    # 名前が長かったらエラー
    if len(username) > Values.USERNAME_MAX_LENGTH:
        return HttpResponse(Response.invalid_value_error("username length"))
    # 名前が空だったらエラー
    if len(username) < 1:
        return HttpResponse(Response.invalid_value_error("empty username"))

    # ユーザがいなかったら作成
    try:
        user = User.objects.get(name=username)
    except User.DoesNotExist:
        user = User.objects.create(name=username, uid=userid)

    challenge = generate_id(Values.CHALLENGE_LENGTH)
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
    exclude_credentials = Key.objects.filter(user=user)
    for c in exclude_credentials:
        options["excludeCredentials"].append({
            "type": "public-key",
            "id": c.credential_id,
            "transports": ["internal"]
        })

    # challengeの保存
    now = timezone.now()
    Session.objects.create(challenge=string_to_base64_url(challenge),
                           user=user, time=now, function="attestation")

    # 古いセッションを削除
    for s in Session.objects.all():
        if now > s.time + timedelta(minutes=Values.SESSION_TIMEOUT_MINUTE):
            s.delete()
    for s in RemoteSession.objects.all():
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
        client_data = ClientData(response['clientDataJSON'])
        # 検証
        client_data.validate_create()
        # challenge取得
        challenge = client_data.challenge

        # AttestationObjectの読み込み
        try:
            attestation_object = AttestationObject(
                response['attestationObject'])
        except UnicodeDecodeError:
            raise FormatException("attestationObject")

        # authDataの検証
        attestation_object.auth_data.validate()

        # attStmtの検証
        attestation_object.validate_att_stmt(client_data.hash)

        # すでに登録済みか確認
        if Key.objects.filter(credential_id=attestation_object.auth_data.credential_id).count() != 0:
            raise InvalidValueException("already registered")

        # challengeの確認
        try:
            session = Session.objects.get(
                challenge=challenge, function="attestation")
        except Session.DoesNotExist:
            raise InvalidValueException("clientDataJson.challenge")

        # 時刻確認
        now = timezone.now()
        if session.time >= now + timedelta(minutes=Values.SESSION_TIMEOUT_MINUTE):
            raise InvalidValueException("session timeout")

        # session削除
        session.delete()

        # 保存
        # Key.objects.create(
        #     user=session.user,
        #     credential_id=attestation_object.auth_data.credential_id,
        #     aaguid=attestation_object.auth_data.aaguid,
        #     alg=attestation_object.alg,
        #     fmt=attestation_object.fmt,
        #     credential_public_key=attestation_object.credential_public_key,
        #     sign_count=attestation_object.auth_data.sign_count,
        #     transports=json.dumps(response['transports']),
        #     regTime=now
        # )

        return HttpResponse(Response.success({'username': session.user.name}))
    except FormatException as e:
        return HttpResponse(Response.format_error(str(e)))
    except InvalidValueException as e:
        return HttpResponse(Response.invalid_value_error(str(e)))
    except UnsupportedException as e:
        return HttpResponse(Response.unsupported_error(str(e)))
    except InternalServerErrorException as e:
        return HttpResponse(Response.internal_server_error(str(e)))
