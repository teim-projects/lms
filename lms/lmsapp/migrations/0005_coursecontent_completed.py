# Generated by Django 5.0 on 2025-02-08 06:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('lmsapp', '0004_remove_courseprogress_completed_contents_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='coursecontent',
            name='completed',
            field=models.BooleanField(default=False),
        ),
    ]
