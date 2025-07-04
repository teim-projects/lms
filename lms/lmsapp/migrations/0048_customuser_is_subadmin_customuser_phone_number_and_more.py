# Generated by Django 5.0 on 2025-06-30 11:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('lmsapp', '0047_remove_customuser_is_subadmin_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='is_subadmin',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='customuser',
            name='phone_number',
            field=models.CharField(blank=True, max_length=15, null=True),
        ),
        migrations.AddField(
            model_name='customuser',
            name='plain_password',
            field=models.CharField(blank=True, max_length=128, null=True),
        ),
        migrations.DeleteModel(
            name='SubAdmin',
        ),
    ]
