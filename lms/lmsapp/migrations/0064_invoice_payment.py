# Generated by Django 5.0 on 2025-07-18 11:27

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('lmsapp', '0063_remove_invoice_payment'),
    ]

    operations = [
        migrations.AddField(
            model_name='invoice',
            name='payment',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='lmsapp.newpayment'),
        ),
    ]
