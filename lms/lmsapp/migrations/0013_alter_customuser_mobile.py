# Generated by Django 4.2 on 2025-06-04 17:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('lmsapp', '0012_alter_customuser_mobile'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='mobile',
            field=models.CharField(max_length=12, unique=True),
        ),
    ]
