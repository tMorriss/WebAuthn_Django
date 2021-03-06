# Generated by Django 3.1.4 on 2021-01-02 07:54

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Key',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.CharField(max_length=30)),
                ('userid', models.CharField(max_length=64)),
                ('credentialId', models.CharField(max_length=300)),
                ('alg', models.IntegerField(default=0)),
                ('credentialPublicKey', models.CharField(max_length=500)),
                ('signCount', models.IntegerField(default=None)),
                ('regTime', models.DateTimeField()),
            ],
        ),
        migrations.CreateModel(
            name='Session',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('challenge', models.CharField(max_length=16)),
                ('username', models.CharField(max_length=30)),
                ('userid', models.CharField(max_length=64)),
                ('time', models.DateTimeField()),
                ('function', models.CharField(max_length=11)),
            ],
        ),
    ]
