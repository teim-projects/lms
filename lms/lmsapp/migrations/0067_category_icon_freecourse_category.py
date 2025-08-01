# Generated by Django 5.0 on 2025-07-23 07:17

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('lmsapp', '0066_paidcourse_category'),
    ]

    operations = [
        migrations.AddField(
            model_name='category',
            name='icon',
            field=models.ImageField(blank=True, null=True, upload_to='category_icons/'),
        ),
        migrations.AddField(
            model_name='freecourse',
            name='category',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='lmsapp.category'),
        ),
    ]
