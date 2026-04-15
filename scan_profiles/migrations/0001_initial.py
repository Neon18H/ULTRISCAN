from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name='ScanProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('name', models.CharField(max_length=120, unique=True)),
                ('description', models.TextField(blank=True)),
                ('host_discovery', models.BooleanField(default=True)),
                ('port_detection', models.BooleanField(default=True)),
                ('version_detection', models.BooleanField(default=True)),
                ('web_detection', models.BooleanField(default=False)),
                ('light_enumeration', models.BooleanField(default=False)),
                ('wordpress_scan', models.BooleanField(default=False)),
            ],
            options={
                'verbose_name': 'Perfil de escaneo',
                'verbose_name_plural': 'Perfiles de escaneo',
                'ordering': ['name'],
            },
        ),
    ]
