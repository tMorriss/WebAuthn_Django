from django.db import models
from webauthn.lib.values import Values


class Key(models.Model):
    username = models.CharField(max_length=50)
    credentialId = models.CharField(max_length=300)
    pubKey = models.CharField(max_length=500)
    signCount = models.IntegerField(default=0)


class Session(models.Model):
    challenge = models.CharField(max_length=Values.CHALLENGE_LENGTH)
    username = models.CharField(max_length=Values.USERNAME_MAX_LENGTH)
    time = models.DateTimeField()
