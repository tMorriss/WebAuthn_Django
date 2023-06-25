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
from webauthn.lib.utils import base64_url_decode, generate_id, string_to_base64_url
from webauthn.lib.values import Values
from webauthn.models import Key, RemoteSession, Session, User


@csrf_exempt
def assertion_options(request):
    try:
        # POSTのみ受付
        if request.method != 'POST':
            return HttpResponse(Response.format_error("http method"))

        post_data = json.loads(request.body)

        challenge = generate_id(Values.CHALLENGE_LENGTH)
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
                    "id": c.credential_id,
                    "transports": c.transports.split(',')
                })

        # challengeの保存
        now = timezone.now()
        Session.objects.create(challenge=string_to_base64_url(challenge),
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
        return HttpResponse(Response.invalid_value_error(str(e)))


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
        client_data = ClientData(response['clientDataJSON'])
        # 検証
        client_data.validate_get()
        # challenge取得
        challenge = client_data.challenge

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
        auth_data = AuthData(base64_url_decode(response['authenticatorData']))
        auth_data.validate()

        # 公開鍵の検証
        try:
            pub_key = Key.objects.get(
                user=user, credential_id=post_data['id'])
        except Key.DoesNotExist:
            raise InvalidValueException('public key is missing')
        data_to_verify = auth_data.auth_data + client_data.hash
        if not PublicKey.verify(
                pub_key.credential_public_key,
                data_to_verify,
                base64_url_decode(response['signature']),
                pub_key.alg):
            raise InvalidValueException('response.signature')

        # signCountの検証
        if pub_key.sign_count != 0 and auth_data.sign_count != 0 and pub_key.sign_count >= auth_data.sign_count:
            raise InvalidValueException('signCount')

        # signCountの更新
        pub_key.sign_count = auth_data.sign_count
        pub_key.save()

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

        return HttpResponse(Response.success({'username': pub_key.user.name}))

    except FormatException as e:
        return HttpResponse(Response.format_error(str(e)))
    except InvalidValueException as e:
        return HttpResponse(Response.invalid_value_error(str(e)))
