from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name='Product',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('name', models.CharField(max_length=120, unique=True)),
                ('vendor', models.CharField(blank=True, max_length=120)),
            ],
            options={'ordering': ['name']},
        ),
        migrations.CreateModel(
            name='RemediationTemplate',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('title', models.CharField(max_length=150)),
                ('body', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='EndOfLifeRule',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('title', models.CharField(max_length=180)),
                ('min_version', models.CharField(blank=True, max_length=50)),
                ('max_version', models.CharField(blank=True, max_length=50)),
                ('port', models.PositiveIntegerField(blank=True, null=True)),
                ('protocol', models.CharField(blank=True, max_length=10)),
                ('required_evidence', models.CharField(blank=True, max_length=150)),
                ('severity', models.CharField(choices=[('info', 'Info'), ('low', 'Low'), ('medium', 'Medium'), ('high', 'High'), ('critical', 'Critical')], default='low', max_length=20)),
                ('cvss', models.DecimalField(decimal_places=1, default=0.0, max_digits=3)),
                ('confidence', models.CharField(choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High')], default='medium', max_length=20)),
                ('description', models.TextField()),
                ('eol_date', models.DateField(blank=True, null=True)),
                ('product', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='endofliferule_rules', to='knowledge_base.product')),
                ('remediation_template', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='knowledge_base.remediationtemplate')),
            ],
            options={'abstract': False},
        ),
        migrations.CreateModel(
            name='MisconfigurationRule',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('title', models.CharField(max_length=180)),
                ('min_version', models.CharField(blank=True, max_length=50)),
                ('max_version', models.CharField(blank=True, max_length=50)),
                ('port', models.PositiveIntegerField(blank=True, null=True)),
                ('protocol', models.CharField(blank=True, max_length=10)),
                ('required_evidence', models.CharField(blank=True, max_length=150)),
                ('severity', models.CharField(choices=[('info', 'Info'), ('low', 'Low'), ('medium', 'Medium'), ('high', 'High'), ('critical', 'Critical')], default='low', max_length=20)),
                ('cvss', models.DecimalField(decimal_places=1, default=0.0, max_digits=3)),
                ('confidence', models.CharField(choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High')], default='medium', max_length=20)),
                ('description', models.TextField()),
                ('product', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='misconfigurationrule_rules', to='knowledge_base.product')),
                ('remediation_template', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='knowledge_base.remediationtemplate')),
            ],
            options={'abstract': False},
        ),
        migrations.CreateModel(
            name='ProductVersionRule',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('from_version', models.CharField(max_length=50)),
                ('to_version', models.CharField(max_length=50)),
                ('note', models.TextField(blank=True)),
                ('product', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='version_rules', to='knowledge_base.product')),
            ],
        ),
        migrations.CreateModel(
            name='VulnerabilityRule',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('title', models.CharField(max_length=180)),
                ('min_version', models.CharField(blank=True, max_length=50)),
                ('max_version', models.CharField(blank=True, max_length=50)),
                ('port', models.PositiveIntegerField(blank=True, null=True)),
                ('protocol', models.CharField(blank=True, max_length=10)),
                ('required_evidence', models.CharField(blank=True, max_length=150)),
                ('severity', models.CharField(choices=[('info', 'Info'), ('low', 'Low'), ('medium', 'Medium'), ('high', 'High'), ('critical', 'Critical')], default='low', max_length=20)),
                ('cvss', models.DecimalField(decimal_places=1, default=0.0, max_digits=3)),
                ('confidence', models.CharField(choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High')], default='medium', max_length=20)),
                ('description', models.TextField()),
                ('cve', models.CharField(blank=True, max_length=40)),
                ('product', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='vulnerabilityrule_rules', to='knowledge_base.product')),
                ('remediation_template', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='knowledge_base.remediationtemplate')),
            ],
            options={'abstract': False},
        ),
        migrations.CreateModel(
            name='ReferenceLink',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('label', models.CharField(max_length=120)),
                ('url', models.URLField()),
                ('vulnerability_rule', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='references', to='knowledge_base.vulnerabilityrule')),
            ],
        ),
    ]
