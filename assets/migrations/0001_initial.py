from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name='Asset',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('name', models.CharField(max_length=120)),
                ('asset_type', models.CharField(choices=[('ip', 'IP'), ('cidr', 'Rango CIDR'), ('domain', 'Dominio'), ('url', 'URL')], max_length=20)),
                ('value', models.CharField(max_length=255)),
                ('description', models.TextField(blank=True)),
                ('criticality', models.CharField(choices=[('low', 'Baja'), ('medium', 'Media'), ('high', 'Alta'), ('critical', 'Crítica')], default='medium', max_length=20)),
                ('status', models.CharField(choices=[('active', 'Activo'), ('inactive', 'Inactivo')], default='active', max_length=20)),
                ('tags', models.CharField(blank=True, max_length=255)),
            ],
            options={
                'verbose_name': 'Activo',
                'verbose_name_plural': 'Activos',
                'ordering': ['-created_at'],
                'indexes': [models.Index(fields=['asset_type', 'value'], name='assets_asset_asset_ty_772f57_idx'), models.Index(fields=['status'], name='assets_asset_status_1e31f2_idx')],
            },
        ),
    ]
