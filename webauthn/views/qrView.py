import json
from datetime import timedelta

from django.http import HttpResponse
from django.shortcuts import render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from webauthn.lib.exceptions import FormatException, InvalidValueException
from webauthn.lib.response import Response
from webauthn.lib.utils import generateId, stringToBase64Url
from webauthn.lib.values import Values
from webauthn.models import RemoteSession, User


@csrf_exempt
def generate(request):
    try:
        # POSTのみ受付
        if request.method != 'POST':
            raise FormatException("http method")
        post_data = json.loads(request.body)

        # username取得
        if Values.USERNAME not in post_data:
            raise FormatException(Values.USERNAME)
        username = post_data[Values.USERNAME]

        # ユーザ取得
        users = User.objects.filter(name=username)
        if users.count() <= 0:
            raise InvalidValueException('username')
        user = users.first()

        # QR用Session生成
        now = timezone.now()
        challenge = stringToBase64Url(generateId(Values.CHALLENGE_LENGTH))
        RemoteSession.objects.create(challenge=challenge,
                                     user=user, time=now, function="qr")

        url = Values.ORIGIN + \
            reverse('qr_verify') + "?challenge=" + challenge

        return HttpResponse(Response.success({'url': url, 'challenge': challenge}))

    except FormatException as e:
        return HttpResponse(Response.formatError(str(e)))


def verify(request):
    try:
        # GETのみ受付
        if request.method != 'GET':
            raise FormatException("http method")

        # challenge取得
        if 'challenge' not in request.GET:
            raise FormatException('challenge')
        challenge = request.GET.get('challenge')

        content = {
            'challenge': challenge
        }
        return render(request, 'qr_verify.html', content)

    except FormatException as e:
        return HttpResponse(Response.formatError(str(e)))


def check(request):
    now = timezone.now()
    try:
        # GETのみ受付
        if request.method != 'GET':
            raise FormatException("http method")

        # challenge取得
        if 'challenge' not in request.GET:
            raise FormatException('challenge')
        challenge = request.GET.get('challenge')

        # RemoteSession取得
        try:
            session = RemoteSession.objects.get(challenge=challenge)
        except User.DoesNotExist:
            raise InvalidValueException("challenge")

        # 認証済みだったらOKを返す
        if session.verified:
            session.delete()

            if session.time >= now + timedelta(minutes=Values.SESSION_TIMEOUT_MINUTE):
                raise InvalidValueException("session timeout")

            return HttpResponse(Response.success({'verified': True}))

        return HttpResponse(Response.success({'verified': False}))

    except FormatException as e:
        return HttpResponse(Response.formatError(str(e)))
    except InvalidValueException as e:
        return HttpResponse(Response.invalidValueError(str(e)))
