from django.db import migrations, models
import django.db.models.deletion


def backfill_assets_org(apps, schema_editor):
    Organization = apps.get_model('accounts', 'Organization')
    Asset = apps.get_model('assets', 'Asset')
    default_org, _ = Organization.objects.get_or_create(name='Default Organization', defaults={'slug': 'default-organization'})
    Asset.objects.filter(organization__isnull=True).update(organization=default_org)


class Migration(migrations.Migration):
    dependencies = [
        ('accounts', '0002_organization_membership_and_user_email_unique'),
        ('assets', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='asset',
            name='organization',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='assets', to='accounts.organization'),
        ),
        migrations.RunPython(backfill_assets_org, migrations.RunPython.noop),
        migrations.AlterField(
            model_name='asset',
            name='organization',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='assets', to='accounts.organization'),
        ),
        migrations.AlterUniqueTogether(name='asset', unique_together={('organization', 'asset_type', 'value')}),
    ]
