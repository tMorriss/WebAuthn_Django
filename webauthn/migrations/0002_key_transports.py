# Generated by Django 3.1.4 on 2021-01-02 08:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('webauthn', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='key',
            name='transports',
            field=models.CharField(default='', max_length=100),
        ),
    ]
