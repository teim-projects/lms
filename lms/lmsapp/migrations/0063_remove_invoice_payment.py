# Generated by Django 5.0 on 2025-07-18 10:45

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('lmsapp', '0062_invoice_payment'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='invoice',
            name='payment',
        ),
    ]
