from django.db import migrations, models
import django.db.models.deletion


def backfill_profiles_org(apps, schema_editor):
    Organization = apps.get_model('accounts', 'Organization')
    ScanProfile = apps.get_model('scan_profiles', 'ScanProfile')
    default_org, _ = Organization.objects.get_or_create(name='Default Organization', defaults={'slug': 'default-organization'})
    ScanProfile.objects.filter(organization__isnull=True).update(organization=default_org)


class Migration(migrations.Migration):
    dependencies = [
        ('accounts', '0002_organization_membership_and_user_email_unique'),
        ('scan_profiles', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='scanprofile',
            name='organization',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='scan_profiles', to='accounts.organization'),
        ),
        migrations.RunPython(backfill_profiles_org, migrations.RunPython.noop),
        migrations.AlterField(
            model_name='scanprofile',
            name='organization',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='scan_profiles', to='accounts.organization'),
        ),
        migrations.AlterField(
            model_name='scanprofile',
            name='name',
            field=models.CharField(max_length=120),
        ),
        migrations.AlterUniqueTogether(name='scanprofile', unique_together={('organization', 'name')}),
    ]
