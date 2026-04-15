from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ('assets', '0001_initial'),
        ('scan_profiles', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='ScanExecution',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('queued', 'Queued'), ('running', 'Running'), ('completed', 'Completed'), ('failed', 'Failed'), ('cancelled', 'Cancelled')], default='pending', max_length=20)),
                ('started_at', models.DateTimeField(blank=True, null=True)),
                ('finished_at', models.DateTimeField(blank=True, null=True)),
                ('duration_seconds', models.PositiveIntegerField(default=0)),
                ('error_message', models.TextField(blank=True)),
                ('summary', models.JSONField(blank=True, default=dict)),
                ('command_executed', models.TextField(blank=True)),
                ('asset', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='scan_executions', to='assets.asset')),
                ('profile', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='scan_executions', to='scan_profiles.scanprofile')),
            ],
        ),
        migrations.CreateModel(
            name='RawEvidence',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('source', models.CharField(default='nmap', max_length=50)),
                ('host', models.CharField(max_length=255)),
                ('payload', models.JSONField(default=dict)),
                ('scan_execution', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='raw_evidences', to='scans.scanexecution')),
            ],
        ),
        migrations.CreateModel(
            name='ServiceFinding',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('host', models.CharField(max_length=255)),
                ('port', models.PositiveIntegerField()),
                ('protocol', models.CharField(max_length=10)),
                ('state', models.CharField(max_length=20)),
                ('service', models.CharField(blank=True, max_length=120)),
                ('product', models.CharField(blank=True, max_length=120)),
                ('version', models.CharField(blank=True, max_length=120)),
                ('banner', models.TextField(blank=True)),
                ('scan_execution', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='service_findings', to='scans.scanexecution')),
            ],
        ),
        migrations.CreateModel(
            name='WebFinding',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('host', models.CharField(max_length=255)),
                ('url', models.URLField()),
                ('title', models.CharField(blank=True, max_length=255)),
                ('technology', models.CharField(blank=True, max_length=120)),
                ('evidence', models.TextField(blank=True)),
                ('scan_execution', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='web_findings', to='scans.scanexecution')),
            ],
        ),
    ]
