import json
from datetime import timedelta

from django.http import HttpResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from webauthn.lib.authData import AuthData
from webauthn.lib.clientData import ClientData
from webauthn.lib.exceptions import FormatException, InvalidValueException
from webauthn.lib.publicKey import PublicKey
from webauthn.lib.response import Response
from webauthn.lib.utils import base64UrlDecode, generateId, stringToBase64Url
from webauthn.lib.values import Values
from webauthn.models import Key, RemoteSession, Session, User


@csrf_exempt
def assertion_options(request):
    try:
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
            try:
                user = User.objects.get(name=username)
            except User.DoesNotExist:
                raise InvalidValueException('username')

            credentials = Key.objects.filter(user=user)
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

        # 古いセッションを削除
        for s in Session.objects.all():
            if now > s.time + timedelta(minutes=Values.SESSION_TIMEOUT_MINUTE):
                s.delete()
        for s in RemoteSession.objects.all():
            if now > s.time + timedelta(minutes=Values.SESSION_TIMEOUT_MINUTE):
                s.delete()

        return HttpResponse(json.dumps(options))

    except InvalidValueException as e:
        return HttpResponse(Response.invalidValueError(str(e)))


@csrf_exempt
def assertion_result(request):
    now = timezone.now()

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
        try:
            session = Session.objects.get(
                challenge=challenge, function="assertion")
        except Session.DoesNotExist:
            raise InvalidValueException("clientDataJson.challenge")

        # 時刻確認
        if session.time >= now + timedelta(minutes=Values.SESSION_TIMEOUT_MINUTE):
            raise InvalidValueException("session timeout")

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
        try:
            pubKey = Key.objects.get(
                user=user, credentialId=post_data['id'])
        except Key.DoesNotExist:
            raise InvalidValueException('public key is missing')
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

        # RemoteChallengeがあったら更新
        if 'remote_challenge' in post_data:
            try:
                s = RemoteSession.objects.get(
                    challenge=post_data['remote_challenge'], user=user)
                if s.time > now + timedelta(minutes=Values.SESSION_TIMEOUT_MINUTE):
                    raise InvalidValueException('remote_challenge')
                s.verified = True
                s.save()

            except User.DoesNotExist:
                raise InvalidValueException('remote_challenge')

        return HttpResponse(Response.success({'username': pubKey.user.name}))

    except FormatException as e:
        return HttpResponse(Response.formatError(str(e)))
    except InvalidValueException as e:
        return HttpResponse(Response.invalidValueError(str(e)))
