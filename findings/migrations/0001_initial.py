from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ('knowledge_base', '0001_initial'),
        ('scans', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Finding',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('title', models.CharField(max_length=200)),
                ('description', models.TextField()),
                ('remediation', models.TextField(blank=True)),
                ('severity', models.CharField(choices=[('info', 'Info'), ('low', 'Low'), ('medium', 'Medium'), ('high', 'High'), ('critical', 'Critical')], max_length=20)),
                ('confidence', models.CharField(choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High')], max_length=20)),
                ('status', models.CharField(choices=[('open', 'Open'), ('accepted_risk', 'Accepted Risk'), ('mitigated', 'Mitigated'), ('remediated', 'Remediated'), ('false_positive', 'False Positive')], default='open', max_length=20)),
                ('analyst_notes', models.TextField(blank=True)),
                ('misconfiguration_rule', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='knowledge_base.misconfigurationrule')),
                ('raw_evidence', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='scans.rawevidence')),
                ('scan_execution', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='findings', to='scans.scanexecution')),
                ('service_finding', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='scans.servicefinding')),
                ('vulnerability_rule', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='knowledge_base.vulnerabilityrule')),
            ],
        ),
    ]
