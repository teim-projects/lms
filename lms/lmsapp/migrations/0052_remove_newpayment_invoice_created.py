# Generated by Django 5.0 on 2025-07-09 06:25

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('lmsapp', '0051_newpayment_invoice_created'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='newpayment',
            name='invoice_created',
        ),
    ]
