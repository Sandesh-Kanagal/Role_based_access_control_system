# Generated by Django 4.2.3 on 2023-08-01 07:14

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("myapp", "0002_rename_users_api_mapped_users"),
    ]

    operations = [
        migrations.RenameField(
            model_name="api",
            old_name="mapped_users",
            new_name="users",
        ),
    ]