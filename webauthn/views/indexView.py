import json

from config.settings.common import TIME_ZONE
from dateutil.tz import gettz
from django.http import HttpResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from webauthn.lib.exceptions import FormatException, InvalidValueException
from webauthn.lib.authenticatorInformation import AuthenticatorInformation
from webauthn.lib.response import Response
from webauthn.lib.values import Values
from webauthn.models import Key, User


def index(request):
    return render(request, 'index.html')


def key_list(request):
    try:
        # GETのみ受付
        if request.method != 'GET':
            raise FormatException("http method")

        # username取得
        if Values.USERNAME not in request.GET:
            raise FormatException(Values.USERNAME)
        username = request.GET.get(Values.USERNAME)

        try:
            user = User.objects.get(name=username)
        except User.DoesNotExist:
            raise InvalidValueException('invalid username')
        keys = Key.objects.filter(
            user=user).order_by('regTime').reverse()

        # information取得
        informations = AuthenticatorInformation()

        response = []
        for k in keys:
            info = informations.get(k.aaguid)
            response.append({
                'pk': k.pk,
                'fmt': k.fmt,
                'credentialId': k.credential_id,
                'aaguid': k.aaguid,
                'name': info['name'] if info is not None else '',
                'icon': info['icon_light'] if info is not None else '',
                'regTime': k.regTime.astimezone(gettz(TIME_ZONE)).strftime('%Y-%m-%d %H:%M:%S'),
                'transports': k.transports,
            })

        return HttpResponse(Response.success({'keys': response}))

    except FormatException as e:
        return HttpResponse(Response.format_error(str(e)))
    except InvalidValueException as e:
        return HttpResponse(Response.invalid_value_error(str(e)))


@csrf_exempt
def delete(request):
    try:
        # POSTのみ受付
        if request.method != 'POST':
            raise FormatException("http method")

        # pk取得
        post_data = json.loads(request.body)
        if 'pk' not in post_data:
            return HttpResponse(Response.format_error("pk"))
        pk = post_data['pk']

        Key.objects.filter(pk=pk).delete()

        if Key.objects.filter(pk=pk).count() > 0:
            return HttpResponse(Response.success())
        else:
            return HttpResponse(Response.internal_server_error('delete key'))

    except FormatException as e:
        return HttpResponse(Response.format_error(str(e)))
