# Generated by Django 4.2.3 on 2023-07-24 18:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0003_alter_useraccount_userid'),
    ]

    operations = [
        migrations.AlterField(
            model_name='useraccount',
            name='userid',
            field=models.UUIDField(default='', primary_key=True, serialize=False),
        ),
    ]
