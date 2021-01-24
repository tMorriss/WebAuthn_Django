from django.urls import path
from webauthn.views.assertionView import assertion_options, assertion_result
from webauthn.views.attestationView import (attestation_options,
                                            attestation_result)
from webauthn.views.indexView import delete, index, key_list
from webauthn.views.qrView import generate, verify

urlpatterns = [
    path('', index, name='index'),
    path('attestation/options', attestation_options, name='attestation_options'),
    path('attestation/result', attestation_result, name='attestation_result'),
    path('assertion/options', assertion_options, name='assertion_options'),
    path('assertion/result', assertion_result, name='assertion_result'),
    path('list', key_list, name='list'),
    path('delete', delete, name='delete'),
    path('qr/generate', generate, name='qr_generate'),
    path('qr/verify', verify, name='qr_verify')
]
