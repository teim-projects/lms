# Generated by Django 5.0 on 2025-04-24 06:02

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('lmsapp', '0008_remove_customuser_mobile'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='mobile',
            field=models.CharField(default='NA', max_length=12),
            preserve_default=False,
        ),
    ]
