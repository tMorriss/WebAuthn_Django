from config.settings.common import TIME_ZONE
from dateutil.tz import gettz
from django.http import HttpResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from webauthn.lib.exceptions import FormatException, InvalidValueException
from webauthn.lib.response import Response
from webauthn.lib.values import Values
from webauthn.models import User, Key
import json


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

        users = User.objects.filter(name=username)
        if users.count() <= 0:
            raise InvalidValueException('invalid username')
        keys = Key.objects.filter(
            user=users.first()).order_by('regTime').reverse()

        response = []
        for k in keys:
            response.append({
                'pk': k.pk,
                'credentialId': k.credentialId,
                'regTime': k.regTime.astimezone(gettz(TIME_ZONE)).strftime('%Y-%m-%d %H:%M:%S')
            })

        return HttpResponse(Response.success({'keys': response}))

    except FormatException as e:
        return HttpResponse(Response.formatError(str(e)))
    except InvalidValueException as e:
        return HttpResponse(Response.invalidValueError(str(e)))


@csrf_exempt
def delete(request):
    try:
        # POSTのみ受付
        if request.method != 'POST':
            raise FormatException("http method")

        # pk取得
        post_data = json.loads(request.body)
        if 'pk' not in post_data:
            return HttpResponse(Response.formatError("pk"))
        pk = post_data['pk']

        Key.objects.filter(pk=pk).delete()

        if Key.objects.filter(pk=pk).count() > 0:
            return HttpResponse(Response.success())
        else:
            return HttpResponse(Response.internalServerError('delete key'))

    except FormatException as e:
        return HttpResponse(Response.formatError(str(e)))
