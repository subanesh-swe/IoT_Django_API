# Generated by Django 4.2.3 on 2023-07-24 18:34

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0002_alter_useraccount_managers_useraccount_date_joined_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='useraccount',
            name='userid',
            field=models.UUIDField(default=uuid.uuid4, primary_key=True, serialize=False),
        ),
    ]