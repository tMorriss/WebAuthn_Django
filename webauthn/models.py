from django.db import models
from webauthn.lib.values import Values


class Key(models.Model):
    username = models.CharField(max_length=Values.USERNAME_MAX_LENGTH)
    userid = models.CharField(max_length=64)
    credentialId = models.CharField(max_length=300)
    alg = models.IntegerField(default=0)
    credentialPublicKey = models.CharField(max_length=500)
    signCount = models.IntegerField(default=None)
    regTime = models.DateTimeField()


class Session(models.Model):
    challenge = models.CharField(max_length=Values.CHALLENGE_LENGTH)
    username = models.CharField(max_length=Values.USERNAME_MAX_LENGTH)
    userid = models.CharField(max_length=64)
    time = models.DateTimeField()
    function = models.CharField(max_length=11)
