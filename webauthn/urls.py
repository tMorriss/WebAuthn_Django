from django.urls import path
from webauthn.views.indexView import index
from webauthn.views.attestationView import attestation_options, attestation_result
from webauthn.views.assertionView import assertion_options, assertion_result

urlpatterns = [
    path('', index, name='index'),
    path('attestation/options', attestation_options, name='attestation_options'),
    path('attestation/result', attestation_result, name='attestation_result'),
    path('assertion/options', assertion_options, name='assertion_options'),
    path('assertion/result', assertion_result, name='assertion_result'),
]
