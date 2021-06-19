from django.db import models
from webauthn.lib.values import Values


class User(models.Model):
    name = models.CharField(max_length=Values.USERNAME_MAX_LENGTH, unique=True)
    uid = models.CharField(max_length=64)


class Key(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    credential_id = models.CharField(max_length=300)
    aaguid = models.CharField(max_length=32, default="")
    alg = models.IntegerField(default=0)
    fmt = models.CharField(max_length=30, default="")
    credential_public_key = models.CharField(max_length=500)
    sign_count = models.IntegerField(default=None)
    transports = models.CharField(max_length=100, default="")
    regTime = models.DateTimeField()


class Session(models.Model):
    challenge = models.CharField(max_length=Values.CHALLENGE_LENGTH)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    time = models.DateTimeField()
    function = models.CharField(max_length=11)


class RemoteSession(Session):
    verified = models.BooleanField(default=False)
