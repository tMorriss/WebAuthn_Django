from django.shortcuts import render
from django.http import HttpResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from webauthn.lib.utils import generateId, stringToBase64Url
from webauthn.lib.values import Values
from webauthn.lib.attestationObject import AttestationObject
from webauthn.lib.clientData import ClientData
from webauthn.lib.exceptions import FormatException, InvalidValueException, UnsupportedException
import json


def index(request):
    return render(request, 'index.html')


@csrf_exempt
def attestation_options(request):
    # POSTのみ受付
    if request.method != 'POST':
        return "error"

    post_data = json.loads(request.body)

    if "email" not in post_data:
        return json.dumps({"status": "error"})
    email = post_data["email"]
    user_id = generateId(64)
    challenge = generateId(16)
    options = {
        "rp": {
            "id": Values.RP_ID,
            "name": "tmorriss.com"
        },
        "user": {
            "id": user_id,
            "name": email,
            "displayName": email
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
    f = open(stringToBase64Url(challenge) + '.challenge', 'w')
    f.write(json.dumps({"id": user_id, "name": email}))
    f.close

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

    except FormatException as e:
        return HttpResponseBadRequest("Format Error (" + str(e) + ")")
    except InvalidValueException as e:
        return HttpResponseBadRequest("Invalid Value (" + str(e) + ")")
    except UnsupportedException as e:
        return HttpResponseBadRequest("Unsupported (" + str(e) + ")")

    return HttpResponse("success")
