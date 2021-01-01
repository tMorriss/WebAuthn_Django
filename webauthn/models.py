from django.db import models
from webauthn.lib.values import Values


class Key(models.Model):
    username = models.CharField(max_length=50)
    credentialId = models.CharField(max_length=300)
    alg = models.IntegerField(default=0)
    credentialPublicKey = models.CharField(max_length=500)
    signCount = models.IntegerField(default=0)
    regTime = models.DateTimeField()


class Session(models.Model):
    challenge = models.CharField(max_length=Values.CHALLENGE_LENGTH)
    username = models.CharField(max_length=Values.USERNAME_MAX_LENGTH)
    time = models.DateTimeField()
    function = models.CharField(max_length=11)
