from django.db import migrations, models
import django.db.models.deletion


def backfill_scans_org(apps, schema_editor):
    Organization = apps.get_model('accounts', 'Organization')
    ScanExecution = apps.get_model('scans', 'ScanExecution')
    RawEvidence = apps.get_model('scans', 'RawEvidence')
    ServiceFinding = apps.get_model('scans', 'ServiceFinding')
    WebFinding = apps.get_model('scans', 'WebFinding')
    default_org, _ = Organization.objects.get_or_create(name='Default Organization', defaults={'slug': 'default-organization'})

    for scan in ScanExecution.objects.select_related('asset').all():
        org = getattr(scan.asset, 'organization', None) or default_org
        scan.organization = org
        scan.save(update_fields=['organization'])

    for model in (RawEvidence, ServiceFinding, WebFinding):
        for item in model.objects.select_related('scan_execution').all():
            item.organization = item.scan_execution.organization or default_org
            item.save(update_fields=['organization'])


class Migration(migrations.Migration):
    dependencies = [
        ('accounts', '0002_organization_membership_and_user_email_unique'),
        ('assets', '0002_asset_organization'),
        ('scan_profiles', '0002_scanprofile_organization'),
        ('scans', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='scanexecution',
            name='organization',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='scan_executions', to='accounts.organization'),
        ),
        migrations.AddField(
            model_name='rawevidence',
            name='organization',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='raw_evidences', to='accounts.organization'),
        ),
        migrations.AddField(
            model_name='servicefinding',
            name='organization',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='service_findings', to='accounts.organization'),
        ),
        migrations.AddField(
            model_name='webfinding',
            name='organization',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='web_findings', to='accounts.organization'),
        ),
        migrations.RunPython(backfill_scans_org, migrations.RunPython.noop),
        migrations.AlterField(
            model_name='scanexecution',
            name='organization',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='scan_executions', to='accounts.organization'),
        ),
        migrations.AlterField(
            model_name='rawevidence',
            name='organization',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='raw_evidences', to='accounts.organization'),
        ),
        migrations.AlterField(
            model_name='servicefinding',
            name='organization',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='service_findings', to='accounts.organization'),
        ),
        migrations.AlterField(
            model_name='webfinding',
            name='organization',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='web_findings', to='accounts.organization'),
        ),
    ]
