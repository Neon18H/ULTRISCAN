from django.db import migrations, models
import django.db.models.deletion


def backfill_findings_org(apps, schema_editor):
    Organization = apps.get_model('accounts', 'Organization')
    Finding = apps.get_model('findings', 'Finding')
    default_org, _ = Organization.objects.get_or_create(name='Default Organization', defaults={'slug': 'default-organization'})
    for finding in Finding.objects.select_related('scan_execution').all():
        finding.organization = finding.scan_execution.organization or default_org
        finding.save(update_fields=['organization'])


class Migration(migrations.Migration):
    dependencies = [
        ('accounts', '0002_organization_membership_and_user_email_unique'),
        ('scans', '0002_multitenant_organization'),
        ('findings', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='finding',
            name='organization',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='findings', to='accounts.organization'),
        ),
        migrations.RunPython(backfill_findings_org, migrations.RunPython.noop),
        migrations.AlterField(
            model_name='finding',
            name='organization',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='findings', to='accounts.organization'),
        ),
        migrations.AlterModelOptions(
            name='finding',
            options={'ordering': ['-created_at']},
        ),
    ]
